"""应用装配：把仓库、端口与各服务组合成一个 ApplicationContext。"""
from __future__ import annotations

import secrets

from ..application.audit_service import AuditSubscriptionService
from ..application.evidence_service import EvidenceService
from ..application.package_service import PackageService
from ..application.review_service import ReviewService
from ..application.ports import Clock, IdGenerator, SystemClock, Uuid4IdGenerator
from ..application.repository import Repository
from ..persistence.sqlite_repo import SqliteRepository


class ApplicationContext:
    def __init__(
        self,
        db_path: str,
        *,
        clock: Clock | None = None,
        ids: IdGenerator | None = None,
        audit_cursor_secret: bytes | None = None,
    ) -> None:
        self.db_path = db_path
        self.repo: Repository = SqliteRepository(db_path)
        self.clock: Clock = clock or SystemClock()
        self.ids: IdGenerator = ids or Uuid4IdGenerator()
        # 游标签名密钥：默认每进程随机；需要跨重启有效的游标时由启动参数注入
        self.audit_cursor_secret = audit_cursor_secret or secrets.token_bytes(32)
        self.evidence = EvidenceService(self.repo, self.clock, self.ids)
        self.packages = PackageService(self.repo, self.clock, self.ids)
        self.reviews = ReviewService(self.repo, self.clock, self.ids)
        self.audit = AuditSubscriptionService(
            self.repo, self.clock, self.ids,
            cursor_secret=self.audit_cursor_secret,
        )

    def close(self) -> None:
        self.repo.close()

    def __enter__(self) -> "ApplicationContext":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
