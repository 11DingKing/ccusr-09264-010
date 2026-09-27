"""审计订阅游标：时间锚点 + HMAC 签名。

游标是服务端签发给订阅方、之后原样回传的不可信输入，因此：

- 负载只含 ``(schema, at, seq)``：``at`` 是规范化 UTC ISO-8601 时间锚点，
  ``seq`` 是同一锚点时刻内已确认到的序列（audit_log 的 rowid），二者共同
  定位重放起点，保证同一时刻的多条事件不会被跳过；
- 负载经规范化 JSON 编码后以 HMAC-SHA256 签名，密钥只由服务端持有；
  解码时**先验签再解析**，任何格式/签名/字段问题都立即抛出
  ``InvalidCursorError``（快速失败），绝不静默从头或从中间重放；
- 同一游标可任意次回传，解码结果恒定——重复确认不会跳过事件。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .errors import InvalidCursorError, ValidationError

CURSOR_SCHEMA = "audit-cursor/v1"
TOKEN_PREFIX = "v1"

# 从头重放的锚点：任何真实事件的 UTC ISO-8601 字符串都排在其后
BEGINNING_OF_TIME = "0001-01-01T00:00:00+00:00"


@dataclass(frozen=True)
class AuditCursor:
    """解码后的重放起点。"""

    anchor_at: str  # 规范化 UTC ISO-8601 时间锚点
    seq: int        # 该锚点时刻内已确认的事件序列（rowid），0 表示尚未确认


def normalize_anchor(value: str) -> str:
    """把 ISO-8601 时刻规范化为 UTC 字符串；非法输入立即拒绝。

    统一换算为 UTC 后，audit_log.at 的字符串序与时间序一致，
    游标比较可直接走索引。
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("时间锚点必须是非空 ISO-8601 字符串")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise ValidationError(f"无法解析时间锚点: {value!r}") from None
    if moment.tzinfo is None:
        raise ValidationError("时间锚点必须带时区（例如 2026-09-25T01:00:00+00:00）")
    return moment.astimezone(timezone.utc).isoformat()


def encode_cursor(anchor_at: str, seq: int, secret: bytes) -> str:
    """把重放起点编码为签名游标串。"""
    payload = json.dumps(
        {"schema": CURSOR_SCHEMA, "at": anchor_at, "seq": int(seq)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    body = _b64url_encode(payload)
    return f"{TOKEN_PREFIX}.{body}.{_sign(body.encode('ascii'), secret)}"


def decode_cursor(token: str, secret: bytes) -> AuditCursor:
    """解码并校验游标；任何问题都抛出 InvalidCursorError（快速失败）。"""
    if not isinstance(token, str):
        raise InvalidCursorError("游标必须是字符串")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise InvalidCursorError("游标格式非法")
    _, body, signature = parts
    # 先验签，通过之前不解析负载
    expected = _sign(body.encode("utf-8"), secret)
    if not hmac.compare_digest(expected, signature):
        raise InvalidCursorError("游标签名不匹配")
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise InvalidCursorError("游标负载无法解码") from None
    if not isinstance(payload, dict) or payload.get("schema") != CURSOR_SCHEMA:
        raise InvalidCursorError("游标模式不匹配")
    at = payload.get("at")
    seq = payload.get("seq")
    if not isinstance(at, str) or not at:
        raise InvalidCursorError("游标缺少时间锚点")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise InvalidCursorError("游标序列非法")
    try:
        anchor = normalize_anchor(at)
    except ValidationError:
        raise InvalidCursorError("游标时间锚点非法") from None
    return AuditCursor(anchor_at=anchor, seq=seq)


def _sign(message: bytes, secret: bytes) -> str:
    return _b64url_encode(hmac.new(secret, message, hashlib.sha256).digest())


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
