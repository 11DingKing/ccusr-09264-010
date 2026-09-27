"""审计订阅游标：时间锚点 + HMAC-SHA256 签名（仅用 Python 标准库）。

游标是不透明令牌，载荷只承载一个 UTC 时间锚点，并用服务端密钥签名。
读取侧永远从“锚点时刻（含）”开始按 (at, audit_id) 升序拉取，因此：

- 支持从任意指定时间点开始重放（签发时锚定该时刻）；
- 重复确认同一游标不会跳过边界时刻的事件（WHERE at >= anchor 为闭区间）；
- 篡改、伪造、格式非法的游标在访问数据库之前即被拒绝（快速失败）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone

from .errors import InvalidCursorError

# 签名用途域分隔：即使将来出现其他类型的令牌，也不能跨用途重放。
PURPOSE = "quality-evidence-audit-cursor/v1"
_PREFIX = "qeac1"


def normalize_anchor(value: str) -> str:
    """校验时间锚点并规范化为 UTC ISO-8601；非法值快速失败。"""
    if not isinstance(value, str) or not value:
        raise InvalidCursorError("时间锚点为空")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise InvalidCursorError("时间锚点不是合法的 ISO-8601 时刻") from exc
    if moment.tzinfo is None:
        raise InvalidCursorError("时间锚点必须带时区偏移")
    return moment.astimezone(timezone.utc).isoformat()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signature(payload: str, secret: str) -> bytes:
    message = PURPOSE.encode("ascii") + b"|" + payload.encode("ascii")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def issue_cursor(anchor_iso: str, secret: str) -> str:
    """把时间锚点签名为不透明游标字符串。"""
    anchor = normalize_anchor(anchor_iso)
    payload = _b64encode(anchor.encode("utf-8"))
    mac = _b64encode(_signature(payload, secret))
    return f"{_PREFIX}.{payload}.{mac}"


def decode_cursor(token: str, secret: str) -> str:
    """验证游标签名，返回规范化后的 UTC 锚点。

    任何格式、编码、签名问题都抛 InvalidCursorError，且不触碰数据库。
    """
    if not isinstance(token, str):
        raise InvalidCursorError("游标格式非法")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _PREFIX or not parts[1] or not parts[2]:
        raise InvalidCursorError("游标格式非法")
    _, payload, mac = parts
    try:
        provided = _b64decode(mac)
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("游标签名编码非法") from exc
    expected = _signature(payload, secret)
    if not hmac.compare_digest(provided, expected):
        raise InvalidCursorError("游标签名无效")
    try:
        anchor = _b64decode(payload).decode("utf-8")
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise InvalidCursorError("游标载荷编码非法") from exc
    # 载荷内的锚点同样必须合法（闭区间查询依赖可比较的 ISO 时刻）
    return normalize_anchor(anchor)
