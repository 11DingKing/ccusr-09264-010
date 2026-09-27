"""审计事件订阅用例：签名游标签发与按锚点重放。

游标只包含时间锚点并由 Python 端 HMAC 签名；读取是纯只读操作：
先验签（非法游标在访问数据库前快速失败），再以闭区间
``at >= anchor`` 按 (at, audit_id) 升序拉取。确认游标不推进任何
服务端状态，因此重复确认同一游标总是返回同样的起点，绝不跳过事件。
"""
from __future__ import annotations

from ..domain import cursor as cursor_token
from ..domain.enums import Role
from ..domain.errors import ValidationError
from ..domain.models import AuditEntry, User
from .base import Service, require_roles

DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 500


class AuditSubscriptionService(Service):
    def __init__(self, repo, clock, ids, cursor_secret: str) -> None:
        super().__init__(repo, clock, ids)
        if not cursor_secret:
            raise ValueError("cursor_secret 不能为空")
        self._secret = cursor_secret

    # ------------------------------------------------------------- 游标签发
    def issue_cursor(
        self, actor: User, *, anchor_at: str | None = None
    ) -> dict:
        """为审计角色签发游标；anchor_at 省略时锚定当前时刻。"""
        require_roles(actor, Role.AUDITOR)
        anchor = self.clock.now_iso() if anchor_at is None else anchor_at
        normalized = cursor_token.normalize_anchor(anchor)
        return {
            "cursor": cursor_token.issue_cursor(normalized, self._secret),
            "anchor_at": normalized,
        }

    # ------------------------------------------------------------- 事件重放
    def read_events(
        self, actor: User, cursor: str | None, *, limit: int = DEFAULT_PAGE_LIMIT
    ) -> dict:
        require_roles(actor, Role.AUDITOR)
        # 无游标视为从当前时刻开始订阅；有游标则先验签，再碰数据库。
        if cursor is None or cursor == "":
            anchor = self.clock.now_iso()
        else:
            anchor = cursor_token.decode_cursor(cursor, self._secret)
        if not isinstance(limit, int) or limit <= 0:
            raise ValidationError("limit 必须是正整数")
        limit = min(limit, MAX_PAGE_LIMIT)

        entries = self.repo.scan_audit(anchor, limit)
        events = [_audit_dict(e) for e in entries]
        result: dict = {
            "anchor_at": anchor,
            "events": events,
            "count": len(events),
        }
        if entries:
            # 下一页锚定最后一条事件的时刻（闭区间）：同刻事件可能重放，
            # 但跨页读取绝不会丢事件。
            result["next_cursor"] = cursor_token.issue_cursor(
                entries[-1].at, self._secret
            )
        else:
            # 没有事件时锚点不变，同一游标继续可重复确认。
            result["next_cursor"] = cursor_token.issue_cursor(anchor, self._secret)
        return result


def _audit_dict(entry: AuditEntry) -> dict:
    return {
        "audit_id": entry.audit_id,
        "package_id": entry.package_id,
        "institution_id": entry.institution_id,
        "actor_id": entry.actor_id,
        "action": entry.action,
        "at": entry.at,
        "detail": entry.detail,
    }
