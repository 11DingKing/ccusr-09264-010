"""审计订阅服务：按签名游标从指定时间点重放审计事件。

规则：
- 仅审计角色可订阅（审计天然拥有跨机构只读视角）；
- 起点由调用方以 ``since``（时间点）或 ``cursor``（上次返回的签名游标）
  指定，二者互斥；都不给则从头重放；
- 游标由服务端 HMAC 签名，解码失败立即报错，绝不静默重定位；
- 读取是只读的：服务端不保存订阅进度，同一游标重读返回同一起点，
  重复确认不会跳过事件；订阅方处理完一页后再持久化 next_cursor，
  崩溃恢复后从最后确认的游标继续即可（at-least-once）。
"""
from __future__ import annotations

from ..domain.audit_cursor import (
    BEGINNING_OF_TIME,
    AuditCursor,
    decode_cursor,
    encode_cursor,
    normalize_anchor,
)
from ..domain.enums import Role
from ..domain.errors import ValidationError
from ..domain.models import AuditEntry, User
from .base import Service, require_roles


class AuditSubscriptionService(Service):
    MAX_LIMIT = 500

    def __init__(self, repo, clock, ids, *, cursor_secret: bytes) -> None:
        super().__init__(repo, clock, ids)
        if not cursor_secret:
            raise ValueError("审计订阅游标需要签名密钥")
        self._cursor_secret = cursor_secret

    # ------------------------------------------------------------ 签发游标
    def issue_cursor(self, actor: User, *, at: str) -> dict:
        """从指定时间点开始订阅：签发锚定该时刻的游标。"""
        require_roles(actor, Role.AUDITOR)
        anchor = normalize_anchor(at)
        return {
            "cursor": encode_cursor(anchor, 0, self._cursor_secret),
            "anchor_at": anchor,
        }

    # ------------------------------------------------------------ 重放事件
    def read_events(
        self,
        actor: User,
        *,
        since: str | None = None,
        cursor: str | None = None,
        limit: int = 200,
    ) -> dict:
        require_roles(actor, Role.AUDITOR)
        if since is not None and cursor is not None:
            raise ValidationError("since 与 cursor 只能二选一")
        limit = self._validate_limit(limit)
        if cursor is not None:
            # 非法游标在此快速失败（InvalidCursorError）
            start = decode_cursor(cursor, self._cursor_secret)
        elif since is not None:
            start = AuditCursor(anchor_at=normalize_anchor(since), seq=0)
        else:
            start = AuditCursor(anchor_at=BEGINNING_OF_TIME, seq=0)
        events = self.repo.list_audit_since(start.anchor_at, start.seq, limit)
        if events:
            next_anchor, next_seq = events[-1].at, events[-1].seq
        else:
            # 没有新事件：游标原地不动，调用方可继续轮询
            next_anchor, next_seq = start.anchor_at, start.seq
        return {
            "events": [self._event_dict(e) for e in events],
            "next_cursor": encode_cursor(next_anchor, next_seq, self._cursor_secret),
        }

    # ------------------------------------------------------------ 内部
    def _validate_limit(self, limit) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit 必须是整数")
        if not 1 <= limit <= self.MAX_LIMIT:
            raise ValidationError(
                "limit 超出范围", details={"max": self.MAX_LIMIT}
            )
        return limit

    @staticmethod
    def _event_dict(entry: AuditEntry) -> dict:
        return {
            "audit_id": entry.audit_id,
            "package_id": entry.package_id,
            "institution_id": entry.institution_id,
            "actor_id": entry.actor_id,
            "action": entry.action,
            "at": entry.at,
            "detail": entry.detail,
        }
