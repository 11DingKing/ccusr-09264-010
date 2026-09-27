"""审计订阅游标：时间锚点、HMAC 签名、重放不跳事件、非法游标快速失败。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from urllib.parse import quote

from service_09252_006.domain.audit_cursor import (
    AuditCursor,
    decode_cursor,
    encode_cursor,
)
from service_09252_006.domain.enums import MaterialKind, Role
from service_09252_006.domain.errors import (
    InvalidCursorError,
    PermissionDeniedError,
    ValidationError,
)
from tests.support import Harness

T0 = "2026-09-25T01:00:00+00:00"  # Harness START


def _emit(h, actor, count=1, advance_seconds=0):
    """产生 count 条审计事件（每次材料登记写一条），事件间隔推进时钟。"""
    for i in range(count):
        if i > 0 and advance_seconds:
            h.clock.advance(seconds=advance_seconds)
        h.ctx.evidence.register_material(
            actor, kind=MaterialKind.SYLLABUS.value, title="课程大纲"
        )


class AuditSubscriptionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-1", Role.INSTITUTION_ADMIN)
        self.auditor = self.h.user("aud-1", Role.AUDITOR, institution_id=None)
        self.svc = self.h.ctx.audit

    def tearDown(self) -> None:
        self.h.close()

    def _actions(self, page):
        return [e["audit_id"] for e in page["events"]]

    # ------------------------------------------------ 从指定时间点开始读取
    def test_read_from_specified_time_anchor(self) -> None:
        _emit(self.h, self.admin, count=3, advance_seconds=60)
        all_events = self.svc.read_events(self.auditor)["events"]
        self.assertEqual(len(all_events), 3)
        t1 = all_events[1]["at"]

        # 锚点含边界事件本身（inclusive）：从 t1 起读到第 2、3 条
        page = self.svc.read_events(self.auditor, since=t1)
        self.assertEqual(
            self._actions(page), [e["audit_id"] for e in all_events[1:]]
        )

        # 锚点落在两条事件之间：只读到其后的
        mid = "2026-09-25T01:01:30+00:00"
        page = self.svc.read_events(self.auditor, since=mid)
        self.assertEqual(self._actions(page), [all_events[2]["audit_id"]])

    def test_anchor_accepts_offsets_and_zulu(self) -> None:
        _emit(self.h, self.admin, count=2, advance_seconds=60)
        t0 = self.svc.read_events(self.auditor)["events"][0]["at"]
        self.assertEqual(t0, T0)
        for equivalent in (
            T0,
            "2026-09-25T01:00:00Z",
            "2026-09-25T09:00:00+08:00",   # 同一时刻的上海时间
            "2026-09-24T20:00:00-05:00",   # 同一时刻的纽约时间
        ):
            page = self.svc.read_events(self.auditor, since=equivalent)
            self.assertEqual(len(page["events"]), 2, equivalent)

    def test_anchor_must_be_timezone_aware(self) -> None:
        with self.assertRaises(ValidationError):
            self.svc.read_events(self.auditor, since="2026-09-25T01:00:00")
        with self.assertRaises(ValidationError):
            self.svc.read_events(self.auditor, since="not-a-time")
        with self.assertRaises(ValidationError):
            self.svc.issue_cursor(self.auditor, at="")

    # -------------------------------------------- 游标：时间锚点 + Python 签名
    def test_cursor_carries_signed_time_anchor(self) -> None:
        issued = self.svc.issue_cursor(self.auditor, at="2026-09-25T09:00:00+08:00")
        token = issued["cursor"]
        self.assertEqual(issued["anchor_at"], T0)

        prefix, body, signature = token.split(".")
        self.assertEqual(prefix, "v1")
        payload = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        )
        self.assertEqual(payload["at"], T0)          # 时间锚点在负载里
        self.assertEqual(payload["seq"], 0)
        self.assertEqual(payload["schema"], "audit-cursor/v1")

        # 签名是服务端密钥的 HMAC-SHA256（Python 侧可验）
        expected = base64.urlsafe_b64encode(
            hmac.new(
                self.h.ctx.audit_cursor_secret,
                body.encode("ascii"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(signature, expected)

        decoded = decode_cursor(token, self.h.ctx.audit_cursor_secret)
        self.assertEqual(decoded, AuditCursor(anchor_at=T0, seq=0))

    # ---------------------------------- 相同游标两次返回同样起点 / 重复确认不跳事件
    def test_same_cursor_twice_returns_same_start(self) -> None:
        _emit(self.h, self.admin, count=4, advance_seconds=60)
        first = self.svc.read_events(self.auditor, limit=2)
        cursor = first["next_cursor"]

        replay_a = self.svc.read_events(self.auditor, cursor=cursor)
        replay_b = self.svc.read_events(self.auditor, cursor=cursor)
        self.assertEqual(replay_a, replay_b)                 # 起点与整页一致
        self.assertEqual(len(replay_a["events"]), 2)
        self.assertEqual(replay_a["next_cursor"], replay_b["next_cursor"])

    def test_repeated_ack_does_not_skip_events(self) -> None:
        _emit(self.h, self.admin, count=5, advance_seconds=60)
        page1 = self.svc.read_events(self.auditor, limit=2)
        page2 = self.svc.read_events(self.auditor, cursor=page1["next_cursor"], limit=2)
        # 订阅端重试：再次确认同一个游标
        page2_retry = self.svc.read_events(
            self.auditor, cursor=page1["next_cursor"], limit=2
        )
        self.assertEqual(self._actions(page2), self._actions(page2_retry))
        page3 = self.svc.read_events(self.auditor, cursor=page2["next_cursor"], limit=2)

        delivered = (
            self._actions(page1) + self._actions(page2) + self._actions(page3)
        )
        all_ids = [e["audit_id"] for e in self.svc.read_events(self.auditor)["events"]]
        self.assertEqual(delivered, all_ids)  # 顺序覆盖全部事件，无跳过

    def test_same_timestamp_events_are_not_skipped(self) -> None:
        # 三条事件落在同一时刻（时钟不推进）
        _emit(self.h, self.admin, count=3)
        page1 = self.svc.read_events(self.auditor, limit=2)
        self.assertEqual(len(page1["events"]), 2)
        page2 = self.svc.read_events(self.auditor, cursor=page1["next_cursor"], limit=2)
        self.assertEqual(len(page2["events"]), 1)  # 同时刻的第三条不被跳过
        page3 = self.svc.read_events(self.auditor, cursor=page2["next_cursor"], limit=2)
        self.assertEqual(page3["events"], [])
        delivered = self._actions(page1) + self._actions(page2)
        self.assertEqual(len(set(delivered)), 3)

    def test_empty_read_keeps_cursor_stable(self) -> None:
        page = self.svc.read_events(self.auditor)
        self.assertEqual(page["events"], [])
        again = self.svc.read_events(self.auditor, cursor=page["next_cursor"])
        self.assertEqual(again["events"], [])
        self.assertEqual(again["next_cursor"], page["next_cursor"])

    # ------------------------------------------------ 非法游标快速失败
    def test_invalid_cursor_fails_fast(self) -> None:
        secret = self.h.ctx.audit_cursor_secret
        good = self.svc.issue_cursor(self.auditor, at=T0)["cursor"]
        body = good.split(".")[1]

        def forged(payload: dict, key: bytes) -> str:
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            b = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            sig = base64.urlsafe_b64encode(
                hmac.new(key, b.encode(), hashlib.sha256).digest()
            ).decode().rstrip("=")
            return f"v1.{b}.{sig}"

        bad_tokens = [
            "not-a-cursor",                       # 结构非法
            "",                                   # 空串
            good[:-2] + "zz",                     # 签名被篡改
            good.replace(body, body[:-1] + "A"),  # 负载被篡改
            forged(                               # 他钥签名
                {"schema": "audit-cursor/v1", "at": T0, "seq": 0}, b"wrong-secret"
            ),
            forged({"schema": "other/v9", "at": T0, "seq": 0}, secret),   # 模式不符
            forged({"schema": "audit-cursor/v1", "seq": 0}, secret),      # 缺锚点
            forged({"schema": "audit-cursor/v1", "at": T0, "seq": -1}, secret),
            forged({"schema": "audit-cursor/v1", "at": "junk", "seq": 0}, secret),
        ]
        for token in bad_tokens:
            with self.assertRaises(InvalidCursorError, msg=token) as ctx:
                self.svc.read_events(self.auditor, cursor=token)
            self.assertEqual(ctx.exception.code, "invalid_cursor")

    def test_cursor_from_other_deployment_rejected(self) -> None:
        foreign = encode_cursor(T0, 0, b"another-deployment-secret")
        with self.assertRaises(InvalidCursorError):
            self.svc.read_events(self.auditor, cursor=foreign)
        # 但本部署签发的游标可正常解码
        local = encode_cursor(T0, 0, self.h.ctx.audit_cursor_secret)
        self.assertEqual(decode_cursor(local, self.h.ctx.audit_cursor_secret).seq, 0)

    # ------------------------------------------------ 参数与权限
    def test_since_and_cursor_are_mutually_exclusive(self) -> None:
        cursor = self.svc.issue_cursor(self.auditor, at=T0)["cursor"]
        with self.assertRaises(ValidationError):
            self.svc.read_events(self.auditor, since=T0, cursor=cursor)

    def test_limit_validation(self) -> None:
        for bad in (0, -1, 10_000, "5", 2.5, True):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                self.svc.read_events(self.auditor, limit=bad)

    def test_only_auditor_may_subscribe(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.svc.read_events(self.admin)
        with self.assertRaises(PermissionDeniedError):
            self.svc.issue_cursor(self.admin, at=T0)


class AuditSubscriptionHttpTests(unittest.TestCase):
    """经 HTTP 边界验证订阅端点与错误码。"""

    def setUp(self) -> None:
        from service_09252_006.api.http_api import HttpApiServer
        from tests.test_http_api import ApiClient

        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        base = f"http://{host}:{port}"
        boot = ApiClient(base, bootstrap="boot-secret")
        boot.request(
            "POST", "/v1/admin/users",
            {"user_id": "admin-1", "roles": ["institution_admin"],
             "institution_id": "inst-a"},
        )
        boot.request(
            "POST", "/v1/admin/users",
            {"user_id": "aud-1", "roles": ["auditor"], "institution_id": None},
        )
        boot.request("POST", "/v1/admin/tokens",
                     {"user_id": "admin-1", "token": "tok-admin"})
        boot.request("POST", "/v1/admin/tokens",
                     {"user_id": "aud-1", "token": "tok-aud"})
        self.admin = ApiClient(base, token="tok-admin")
        self.auditor = ApiClient(base, token="tok-aud")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def test_subscribe_over_http(self) -> None:
        self.admin.request(
            "POST", "/v1/materials", {"kind": "syllabus", "title": "大纲"}
        )
        # 签发游标：从指定时间点开始
        status, body = self.auditor.request(
            "POST", "/v1/audit/cursors", {"at": "2026-09-25T09:00:00+08:00"}
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(body["anchor_at"], T0)

        # 同一游标两次读取，起点相同
        cursor = quote(body["cursor"], safe="")
        status, page_a = self.auditor.request("GET", f"/v1/audit/events?cursor={cursor}")
        self.assertEqual(status, 200, page_a)
        status, page_b = self.auditor.request("GET", f"/v1/audit/events?cursor={cursor}")
        self.assertEqual(page_a, page_b)
        self.assertEqual(len(page_a["events"]), 1)
        self.assertEqual(page_a["events"][0]["action"], "material.registered")

        # since 参数（URL 编码后的 ISO 时刻）
        status, page = self.auditor.request(
            "GET", "/v1/audit/events?since=" + quote(T0, safe="")
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(page["events"]), 1)

    def test_invalid_cursor_over_http_is_400(self) -> None:
        status, body = self.auditor.request("GET", "/v1/audit/events?cursor=garbage")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_cursor")

    def test_non_auditor_over_http_is_403(self) -> None:
        status, body = self.admin.request("GET", "/v1/audit/events")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")


if __name__ == "__main__":
    unittest.main()
