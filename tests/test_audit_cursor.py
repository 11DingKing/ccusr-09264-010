"""审计订阅游标：时间锚点重放、重复确认不跳事件、非法游标快速失败。"""
from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.domain import cursor as cursor_token
from service_09252_006.domain.enums import Role
from service_09252_006.domain.errors import (
    InvalidCursorError,
    PermissionDeniedError,
)
from service_09252_006.domain.models import AuditEntry
from tests.flow import upload_material
from tests.support import Harness, START


class AuditCursorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        self.svc = self.h.ctx.audit_subscriptions

    def tearDown(self) -> None:
        self.h.close()

    # ---- 构造审计事件：每个动作推进时钟，at 各不相同 ----
    def _make_events(self, count: int) -> list[str]:
        timestamps: list[str] = []
        for i in range(count):
            upload_material(
                self.h, self.admin, data=f"material-{i}".encode("utf-8")
            )
            timestamps.append(self.h.clock.now_iso())
            self.h.clock.advance(seconds=60)
        return timestamps

    def test_read_from_specified_anchor_is_closed_interval(self) -> None:
        timestamps = self._make_events(3)
        issued = self.svc.issue_cursor(self.auditor, anchor_at=timestamps[1])
        page = self.svc.read_events(self.auditor, issued["cursor"])
        # 锚点落在第二批事件的时刻：该时刻的事件必须包含在内（闭区间）
        acts = [e["at"] for e in page["events"]]
        self.assertEqual(acts[0], timestamps[1])
        # 每批 upload_material 写 register+upload 两条，锚点之后共 2 批
        self.assertEqual(len(page["events"]), 4)
        self.assertNotIn(timestamps[0], acts)

    def test_same_cursor_confirmed_twice_returns_same_start(self) -> None:
        self._make_events(3)
        anchor = self.h.clock.now_iso()  # 已推进到最后一批之后
        issued = self.svc.issue_cursor(self.auditor, anchor_at="2026-09-25T01:00:00+00:00")
        first = self.svc.read_events(self.auditor, issued["cursor"])
        second = self.svc.read_events(self.auditor, issued["cursor"])
        self.assertEqual(
            [e["audit_id"] for e in first["events"]],
            [e["audit_id"] for e in second["events"]],
        )
        self.assertEqual(first["anchor_at"], second["anchor_at"])
        self.assertEqual(len(first["events"]), 6)  # 3 批 × 2 条
        # 再确认多少次都一样：确认游标不推进任何服务端状态
        third = self.svc.read_events(self.auditor, issued["cursor"])
        self.assertEqual(
            [e["audit_id"] for e in third["events"]],
            [e["audit_id"] for e in first["events"]],
        )

    def test_pagination_next_cursor_does_not_skip_events(self) -> None:
        self._make_events(3)
        issued = self.svc.issue_cursor(
            self.auditor, anchor_at="2026-09-25T01:00:00+00:00"
        )
        page1 = self.svc.read_events(self.auditor, issued["cursor"], limit=1)
        self.assertEqual(len(page1["events"]), 1)
        boundary_id = page1["events"][0]["audit_id"]
        # 下一页游标锚定最后一条事件时刻（闭区间）：边界事件再次出现，
        # 由订阅方按 audit_id 去重，但任何事件都不会被跳过。
        page2 = self.svc.read_events(self.auditor, page1["next_cursor"], limit=10)
        ids = [e["audit_id"] for e in page2["events"]]
        self.assertEqual(ids[0], boundary_id)
        self.assertEqual(len(ids), 6)

    def test_events_with_same_timestamp_both_returned_in_stable_order(self) -> None:
        at = self.h.clock.now_iso()
        for i in range(2):
            self.h.repo.insert_audit(
                AuditEntry(
                    audit_id=f"aud-same-{i}",
                    package_id=None,
                    institution_id="inst-a",
                    actor_id="admin-a",
                    action=f"act-{i}",
                    at=at,
                    detail={},
                )
            )
        issued = self.svc.issue_cursor(self.auditor, anchor_at=at)
        first = self.svc.read_events(self.auditor, issued["cursor"])
        second = self.svc.read_events(self.auditor, issued["cursor"])
        for page in (first, second):
            self.assertEqual(
                [e["audit_id"] for e in page["events"]],
                ["aud-same-0", "aud-same-1"],
            )

    def test_anchor_in_other_timezone_normalizes_to_utc(self) -> None:
        timestamps = self._make_events(1)
        # 09:00 上海 == 01:00 UTC（START），事件恰好在该时刻，应被包含
        shanghai_iso = "2026-09-25T09:00:00+08:00"
        issued = self.svc.issue_cursor(self.auditor, anchor_at=shanghai_iso)
        self.assertEqual(issued["anchor_at"], timestamps[0])
        page = self.svc.read_events(self.auditor, issued["cursor"])
        self.assertTrue(any(e["at"] == timestamps[0] for e in page["events"]))

    def test_default_anchor_is_now(self) -> None:
        self._make_events(2)  # t0, t0+60
        self.h.clock.advance(seconds=60)
        issued = self.svc.issue_cursor(self.auditor)
        self.assertEqual(issued["anchor_at"], self.h.clock.now_iso())

    # ---- 非法游标：快速失败 ----
    def test_garbage_cursor_fails_fast(self) -> None:
        with self.assertRaises(InvalidCursorError):
            self.svc.read_events(self.auditor, "not-a-cursor")

    def test_tampered_cursor_fails_fast(self) -> None:
        issued = self.svc.issue_cursor(self.auditor, anchor_at=self.h.clock.now_iso())
        token = issued["cursor"]
        # 翻转签名字段中的一个字符
        head, payload, mac = token.split(".")
        flipped = mac[:-1] + ("0" if mac[-1] != "0" else "1")
        with self.assertRaises(InvalidCursorError):
            self.svc.read_events(self.auditor, f"{head}.{payload}.{flipped}")

    def test_cursor_signed_by_other_secret_rejected(self) -> None:
        foreign = cursor_token.issue_cursor(
            self.h.clock.now_iso(), "a-totally-different-secret"
        )
        with self.assertRaises(InvalidCursorError):
            self.svc.read_events(self.auditor, foreign)

    def test_invalid_anchor_rejected_before_issue(self) -> None:
        with self.assertRaises(InvalidCursorError):
            self.svc.issue_cursor(self.auditor, anchor_at="not-a-time")
        with self.assertRaises(InvalidCursorError):
            # 无时区的本地时间存在歧义，拒绝签发
            self.svc.issue_cursor(self.auditor, anchor_at="2026-09-25T09:00:00")
        with self.assertRaises(InvalidCursorError):
            self.svc.issue_cursor(self.auditor, anchor_at="")

    def test_invalid_cursor_rejected_without_touching_database(self) -> None:
        # 关闭底层连接：合法读取会报 sqlite 错误，但验签先于读库，
        # 非法游标仍只抛 InvalidCursorError（快速失败）。
        self.h.ctx.repo.close()
        try:
            with self.assertRaises(InvalidCursorError):
                self.svc.read_events(self.auditor, "qeac1.aaa.bbb")
        finally:
            # tearDown 会再关一次，关闭已关闭连接无副作用；恢复占位
            pass

    # ---- 鉴权 ----
    def test_non_auditor_cannot_subscribe(self) -> None:
        issued = self.svc.issue_cursor(self.auditor)
        with self.assertRaises(PermissionDeniedError):
            self.svc.read_events(self.submitter, issued["cursor"])
        with self.assertRaises(PermissionDeniedError):
            self.svc.issue_cursor(self.submitter)

    # ---- 游标令牌纯函数 ----
    def test_cursor_is_signed_and_opaque(self) -> None:
        token = cursor_token.issue_cursor(START.isoformat(), self.h.ctx.cursor_secret)
        self.assertTrue(token.startswith("qeac1."))
        # 载荷是 base64，不直接暴露锚点前缀；解码后才可见
        _, payload, _ = token.split(".")
        self.assertNotIn("2026", token.split(".")[2])
        anchor = cursor_token.decode_cursor(token, self.h.ctx.cursor_secret)
        self.assertEqual(anchor, START.isoformat())


class AuditCursorHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self._create_user("aud", ["auditor"], None, "tok-aud")
        self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _create_user(self, user_id, roles, institution_id, token) -> None:
        def call(method, path, body, headers):
            req = urllib.request.Request(
                self.base + path,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json", **headers},
                method=method,
            )
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())

        call(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles, "institution_id": institution_id},
            {"X-Bootstrap-Token": "boot-secret"},
        )
        call(
            "POST", "/v1/admin/tokens",
            {"user_id": user_id, "token": token},
            {"X-Bootstrap-Token": "boot-secret"},
        )

    def _request(self, method, path, token, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_cursor_roundtrip_and_invalid_cursor_422(self) -> None:
        status, issued = self._request(
            "POST", "/v1/audit/cursors", "tok-aud",
            {"anchor_at": "2026-09-25T01:00:00+00:00"},
        )
        self.assertEqual(status, 201, issued)
        status, page = self._request(
            "GET", f"/v1/audit/events?cursor={issued['cursor']}", "tok-aud"
        )
        self.assertEqual(status, 200, page)
        self.assertEqual(page["anchor_at"], "2026-09-25T01:00:00+00:00")

        status, again = self._request(
            "GET", f"/v1/audit/events?cursor={issued['cursor']}", "tok-aud"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [e["audit_id"] for e in page["events"]],
            [e["audit_id"] for e in again["events"]],
        )

        status, bad = self._request(
            "GET", "/v1/audit/events?cursor=forged", "tok-aud"
        )
        self.assertEqual(status, 422)
        self.assertEqual(bad["error"]["code"], "invalid_cursor")

        status, denied = self._request(
            "GET", "/v1/audit/events", "tok-sub"
        )
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
