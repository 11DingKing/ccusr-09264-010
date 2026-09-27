"""应用装配：把仓库、端口与各服务组合成一个 ApplicationContext。"""
from __future__ import annotations

import os

from ..application.audit_subscription import AuditSubscriptionService
from ..application.evidence_service import EvidenceService
from ..application.package_service import PackageService
from ..application.review_service import ReviewService
from ..application.ports import Clock, IdGenerator, SystemClock, Uuid4IdGenerator
from ..application.repository import Repository
from ..persistence.sqlite_repo import SqliteRepository

# 开发/测试默认密钥；生产部署必须通过 cursor_secret 参数或
# QE_CURSOR_SECRET 环境变量覆盖，否则签出的游标不可信。
DEFAULT_CURSOR_SECRET = "dev-only-cursor-secret-change-me"


class ApplicationContext:
    def __init__(
        self,
        db_path: str,
        *,
        clock: Clock | None = None,
        ids: IdGenerator | None = None,
        cursor_secret: str | None = None,
    ) -> None:
        self.db_path = db_path
        self.repo: Repository = SqliteRepository(db_path)
        self.clock: Clock = clock or SystemClock()
        self.ids: IdGenerator = ids or Uuid4IdGenerator()
        self.cursor_secret = (
            cursor_secret
            or os.environ.get("QE_CURSOR_SECRET")
            or DEFAULT_CURSOR_SECRET
        )
        self.evidence = EvidenceService(self.repo, self.clock, self.ids)
        self.packages = PackageService(self.repo, self.clock, self.ids)
        self.reviews = ReviewService(self.repo, self.clock, self.ids)
        self.audit_subscriptions = AuditSubscriptionService(
            self.repo, self.clock, self.ids, self.cursor_secret
        )

    def close(self) -> None:
        self.repo.close()

    def __enter__(self) -> "ApplicationContext":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
