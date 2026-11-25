"""단말 me·신청·묶음 내려받기 경로와 보고 응답의 범위 목록: 인증, 오류 매핑, 경로 탐색 차단."""

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from plugin_helpers import KEY
from test_endpoint_routes import KEY_HEADER, FakeDatabase, build, post

from mint_litellm.endpoint.refresh import revoke_names, scoped_desired

ME = "/mint/v1/endpoint/me"
INTAKES = "/mint/v1/endpoint/intakes"
REPORT = "/mint/v1/endpoint/report"
PACK = "a" * 64
OTHER = "b" * 64
WHEEL = "demo-1.0-py3-none-any.whl"
UNTIL = datetime(2030, 1, 1, tzinfo=UTC)
CONTRACT = {"schema_version": 2, "executable": "/usr/bin/python3", "argv": ["-m", "demo"],
            "pack": {"sha256": PACK, "runtime": "python3", "python": "3.12",
                     "entry": "demo.server:main"}}
ROW = {"server_id": "demo", "pack_sha256": PACK, "permit_until": UNTIL, "exec_contract": CONTRACT,
       "pack_manifest": {"files": [{"name": WHEEL, "sha256": "c" * 64, "size": 3}]}}
HEADERS = {"Authorization": "Bearer sk-other"}


@pytest.fixture
def scope(monkeypatch, tmp_path):
    """키가 닿는 묶음 서버 한 개와 볼륨의 묶음 파일."""
    folder = tmp_path / "packs" / PACK
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text("{}")
    (folder / WHEEL).write_bytes(b"whl")
    (folder / "secret.txt").write_text("no")
    (tmp_path / "packs" / OTHER).mkdir()
    (tmp_path / "packs" / OTHER / "manifest.json").write_text("{}")
    monkeypatch.setenv("MINT_PACKS_DIR", str(tmp_path / "packs"))
    calls = {"scope": [], "submit": []}

    async def endpoint_scope(self, instance_id, key_token):
        calls["scope"].append(key_token)
        return [ROW] if key_token == KEY else []

    async def remote_servers(self, instance_id, key_token):
        if isinstance(calls.get("remote_raise"), Exception):
            raise calls["remote_raise"]
        return ["ms_learn"] if key_token == KEY else []

    async def my_intakes(self, instance_id, key_token):
        return [{"id": UUID(int=1), "server_id": "demo", "status": "received", "decision": None,
                 "reason": None, "created_at": UNTIL}]

    async def submit(self, key_token, request_id, payload):
        calls["submit"].append((key_token, request_id, payload))
        if isinstance(calls.get("raise"), Exception):
            raise calls["raise"]
        return UUID(int=2)

    calls["inspection_pack"] = None

    async def inspection_pack(self, instance_id, key_token, server_id, pack_sha256):
        return calls["inspection_pack"]

    async def inspections(self, instance_id, key_token):
        return calls.get("inspections", [])

    async def inspection_start(self, instance_id, key_token, inspection_id):
        calls.setdefault("start", []).append((key_token, inspection_id))
        if isinstance(calls.get("raise"), Exception):
            raise calls["raise"]

    async def inspection_submit(self, instance_id, key_token, inspection_id, body):
        calls.setdefault("result", []).append((key_token, inspection_id, body))
        if isinstance(calls.get("raise"), Exception):
            raise calls["raise"]

    for name, fn in (("endpoint_scope", endpoint_scope), ("endpoint_my_intakes", my_intakes),
                     ("endpoint_remote_servers", remote_servers),
                     ("endpoint_submit_intake", submit),
                     ("endpoint_inspection_pack", inspection_pack),
                     ("endpoint_inspections", inspections),
                     ("endpoint_inspection_start", inspection_start),
                     ("endpoint_inspection_submit", inspection_submit)):
        monkeypatch.setattr(FakeDatabase, name, fn, raising=False)
    return calls


def intake(**override):
    data = {"request_id": str(UUID(int=7)), "server_id": "demo",
            "spec": {"index": "pypi", "name": "demo", "version": "1.0", "extras": [],
                     "command": "demo", "argv": []},
            "network": "none", "purpose": "x", "data_grade": "internal"}
    return data | override


def test_me_lists_scope_and_recent_intakes_for_the_calling_key(tmp_path, scope):
    client, _ = build(tmp_path)
    answer = client.get(ME, headers=KEY_HEADER).json()
    assert answer["user"] == "u1"
    assert answer["servers"] == [{"server_id": "demo", "pack_sha256": PACK,
                                  "permit_until": UNTIL.isoformat(), "status": "approved"}]
    assert answer["intakes"][0]["id"] == str(UUID(int=1))
    assert answer["intakes"][0]["stage"] == "received"
    assert answer["intakes"][0]["next"] == "검사가 끝나기를 기다림"
    assert answer["remote_servers"] == ["ms_learn"]
    assert client.get(ME).status_code == 401
    assert client.get(ME, headers=HEADERS).json()["servers"] == []
    assert client.get(ME, headers=HEADERS).json()["remote_servers"] == []


def test_me_still_answers_when_the_remote_approvals_cannot_be_read(tmp_path, scope):
    scope["remote_raise"] = RuntimeError("down")
    client, _ = build(tmp_path)
    answer = client.get(ME, headers=KEY_HEADER).json()
    assert answer["remote_servers"] == [] and len(answer["servers"]) == 1


def test_an_intake_is_passed_to_the_db_function_without_identity(tmp_path, scope):
    client, _ = build(tmp_path)
    answer = post(client, INTAKES, intake())
    assert answer.status_code == 201 and answer.json() == {"id": str(UUID(int=2))}
    key, request_id, payload = scope["submit"][0]
    assert key == KEY and request_id == UUID(int=7) and "request_id" not in payload
    assert post(client, INTAKES, intake(user_id="u9")).status_code == 422
    assert post(client, INTAKES, intake(), headers={}).status_code == 401


@pytest.mark.parametrize(("message", "status"), [
    ("MINT-CONFLICT: same request id", 409), ("MINT-QUOTA: daily limit", 429),
    ("MINT-INVALID: server id", 400), ("connection lost", 503)])
def test_intake_errors_map_to_http_statuses(tmp_path, scope, message, status):
    scope["raise"] = RuntimeError(message)
    client, _ = build(tmp_path)
    assert post(client, INTAKES, intake()).status_code == status


@pytest.mark.parametrize("override", [
    {"observed_tools": [{"name": f"t{i}", "input_schema": {}} for i in range(201)]},
    {"network": "hosts"}, {"allowed_hosts": ["a.example.com"]},
    {"spec": {"index": "git", "name": "d", "version": "1", "command": "d"}},
    {"server_id": "../x"}, {"request_id": "nope"}])
def test_a_malformed_intake_is_refused_before_the_db(tmp_path, scope, override):
    client, _ = build(tmp_path)
    assert post(client, INTAKES, intake(**override)).status_code == 422
    assert scope["submit"] == []


def test_the_intake_body_is_limited_to_256_kib(tmp_path, scope):
    client, _ = build(tmp_path)
    assert post(client, INTAKES, intake(purpose="x" * (260 * 1024))).status_code == 413
    ok = intake(observed_tools=[{"name": f"t{i}", "input_schema": {}} for i in range(200)])
    assert post(client, INTAKES, ok).status_code == 201


def pack(client, server="demo", sha=PACK, file="manifest.json", headers=KEY_HEADER):
    return client.get(f"/mint/v1/endpoint/packs/{server}/{sha}/{file}", headers=headers)


def test_a_pack_file_is_sent_only_for_a_pair_in_scope_and_listed_in_the_manifest(tmp_path, scope):
    client, _ = build(tmp_path)
    assert pack(client).content == b"{}"
    assert pack(client, file=WHEEL).content == b"whl"
    assert pack(client, file="secret.txt").status_code == 404  # manifest에 없는 파일
    assert pack(client, sha=OTHER).status_code == 404  # 범위에 없는 묶음
    assert pack(client, server="other").status_code == 404
    assert pack(client, headers=HEADERS).status_code == 404  # 범위 밖 키
    assert pack(client, headers={}).status_code == 401


@pytest.mark.parametrize("file", ["..%2Fsecret.txt", "%2E%2E%2F" + OTHER + "%2Fmanifest.json",
                                  "..", "%5C..%5Csecret.txt"])
def test_a_pack_path_cannot_leave_the_pack_folder(tmp_path, scope, file):
    client, _ = build(tmp_path)
    assert pack(client, file=file).status_code == 404
    assert pack(client, sha="..").status_code == 404


def test_the_report_answer_carries_the_scoped_list_and_the_revoke_names(tmp_path, scope,
                                                                         monkeypatch):
    async def report_install(self, instance_id, key_token, **fields):
        return "recorded"

    async def registered(self, instance_id):
        from types import SimpleNamespace as N
        return [N(server_id=n, identity_kind="stdio", status="approved") for n in ("demo", "old")]

    async def legacy_desired(self, instance_id, key_token):
        return scoped_desired(await self.endpoint_scope(instance_id, key_token))

    monkeypatch.setattr(FakeDatabase, "report_install", report_install, raising=False)
    monkeypatch.setattr(FakeDatabase, "registered_servers", registered, raising=False)
    monkeypatch.setattr(FakeDatabase, "desired_servers", legacy_desired, raising=False)

    async def revoke(self, instance_id, reported, desired):
        from mint_litellm.endpoint.refresh import revoke_names as names
        return names({"demo": "approved", "old": "approved"}, reported, desired)

    monkeypatch.setattr(FakeDatabase, "revoke_servers", revoke, raising=False)
    client, _ = build(tmp_path)
    body = {"kit_version": "k" * 64, "action": "installed", "mode": "managed",
            "mcp_servers": [f"s{i}" for i in range(255)] + ["old"]}
    answer = post(client, REPORT, body).json()
    assert answer["desired"][0]["pack_sha256"] == PACK
    assert answer["revoke"] == ["old"]
    assert post(client, REPORT, {**body, "mcp_servers": ["x"] * 257}).status_code == 422
    assert json.dumps(answer)


def test_scoped_desired_lists_only_what_the_scope_returns():
    plain = {"server_id": "b", "pack_sha256": None, "permit_until": UNTIL,
             "exec_contract": {"executable": "/usr/bin/node", "argv": [],
                               "executable_sha256": "ab" * 32, "schema_version": 1}}
    items = scoped_desired([ROW, plain])
    assert [i["name"] for i in items] == ["b", "demo"]
    assert items[1]["pack_sha256"] == PACK and items[1]["permit_until"] == UNTIL.isoformat()
    assert "pack_sha256" not in items[0]
    assert scoped_desired([]) == []


def test_revoke_names_are_reported_managed_servers_outside_the_scope():
    statuses = {"a": "approved", "b": "approved", "c": "revoked"}
    assert revoke_names(statuses, ["a", "b", "c", "mine"], ["a"]) == ["b"]


# --- 검사용 승인 ----------------------------------------------------------------------------

INSPECT_ID = str(UUID(int=9))
START = f"/mint/v1/endpoint/inspections/{INSPECT_ID}/start"
RESULT = f"/mint/v1/endpoint/inspections/{INSPECT_ID}/result"
TOOL = {"name": "decompile", "description": "d", "inputSchema": {"type": "object"}}


def result(**override):
    return {"pack_sha256": PACK, "complete": True, "tools": [TOOL]} | override


def test_a_pack_outside_the_scope_is_sent_for_a_live_inspection_of_this_key_only(tmp_path, scope):
    client, _ = build(tmp_path)
    assert pack(client, sha=OTHER).status_code == 404
    scope["inspection_pack"] = {"server_id": "demo", "pack_sha256": OTHER,
                                "pack_manifest": {"files": []}}
    assert pack(client, sha=OTHER).content == b"{}"
    assert pack(client, sha=OTHER, file=WHEEL).status_code == 404  # manifest에 없는 파일


def test_the_report_lists_inspections_only_for_a_kit_that_declares_the_capability(
        tmp_path, scope, monkeypatch):
    async def report_install(self, instance_id, key_token, **fields):
        return "recorded"

    async def registered(self, instance_id):
        return []

    async def desired(self, instance_id, key_token):
        return []

    for name, fn in (("report_install", report_install), ("registered_servers", registered),
                     ("desired_servers", desired)):
        monkeypatch.setattr(FakeDatabase, name, fn, raising=False)
    scope["inspections"] = [{"id": UUID(int=9), "intake_id": UUID(int=3), "server_id": "demo",
                             "pack_sha256": PACK, "contract": CONTRACT, "expires_at": UNTIL}]
    client, _ = build(tmp_path)
    base = {"kit_version": "k", "action": "installed", "mode": "managed", "mcp_servers": []}
    assert "inspections" not in post(client, REPORT, base).json()
    assert "inspections" not in post(client, REPORT, {**base, "capabilities": ["x"]}).json()
    got = post(client, REPORT, {**base, "capabilities": ["inspect", "future"]}).json()
    assert got["inspections"] == [{
        "id": INSPECT_ID, "intake_id": str(UUID(int=3)), "server": "demo", "pack_sha256": PACK,
        "contract": CONTRACT, "expires_at": UNTIL.isoformat()}]
    assert post(client, REPORT, {**base, "capabilities": ["a"] * 9}).status_code == 422
    assert post(client, REPORT, {**base, "capabilities": ["a" * 33]}).status_code == 422


def test_start_and_result_reach_the_db_with_the_calling_key(tmp_path, scope):
    client, _ = build(tmp_path)
    assert post(client, START, {}).json() == {"started": True}
    assert scope["start"] == [(KEY, UUID(INSPECT_ID))]
    detail = {"stage": "sandbox", "exit_code": 2, "stderr_tail": "no bwrap"}
    assert post(client, RESULT, result(complete=False, tools=[], detail=detail)).json() == {
        "recorded": True}
    (_, inspection, sent) = scope["result"][0]
    assert inspection == UUID(INSPECT_ID) and sent["detail"] == detail and sent["complete"] is False
    assert post(client, START, {}, headers={}).status_code == 401
    assert post(client, RESULT, result(), headers={}).status_code == 401


@pytest.mark.parametrize(("message", "status"), [
    ("MINT-NOTFOUND: no such inspection", 404), ("MINT-CONFLICT: already", 409),
    ("MINT-INVALID: result", 400), ("MINT-KEY: key not accepted", 404), ("lost", 503)])
def test_inspection_errors_map_to_http_statuses(tmp_path, scope, message, status):
    scope["raise"] = RuntimeError(message)
    client, _ = build(tmp_path)
    assert post(client, START, {}).status_code == status
    assert post(client, RESULT, result()).status_code == status


@pytest.mark.parametrize("override", [
    {"tools": [TOOL] * 201}, {"pack_sha256": "zz"}, {"complete": "yes"}, {"extra": 1},
    {"detail": {"stderr_tail": "x" * 2049}}, {"detail": {"unknown": 1}}])
def test_a_malformed_result_is_refused_before_the_db(tmp_path, scope, override):
    client, _ = build(tmp_path)
    assert post(client, RESULT, result(**override)).status_code == 422
    assert "result" not in scope
    assert client.post("/mint/v1/endpoint/inspections/nope/start", headers=KEY_HEADER
                       ).status_code == 422


def test_the_result_body_is_limited_to_256_kib(tmp_path, scope):
    client, _ = build(tmp_path)
    big = [{"name": "t", "description": "x" * 1000} for _ in range(200)]
    assert post(client, RESULT, result(tools=big)).status_code == 200  # 약 200 KB
    huge = [{"name": "t", "description": "x" * 2000} for _ in range(200)]
    assert post(client, RESULT, result(tools=huge)).status_code == 413


def test_an_intake_may_carry_env_values_and_the_kit_key_may_call_the_new_paths(tmp_path, scope):
    from mint_litellm.endpoint.routes import KIT_KEY_ROUTES

    client, _ = build(tmp_path)
    assert post(client, INTAKES, intake(env={"GHIDRA_INSTALL_DIR": "/opt/ghidra"})
                ).status_code == 201
    assert scope["submit"][-1][2]["env"] == {"GHIDRA_INSTALL_DIR": "/opt/ghidra"}
    assert post(client, INTAKES, intake(env={"1x": "a"})).status_code == 422
    assert "/mint/v1/endpoint/inspections/*" in KIT_KEY_ROUTES


ACCESS = "/mint/v1/endpoint/access-requests"


def test_access_requests_go_to_the_db_with_the_calling_key_only(tmp_path, scope, monkeypatch):
    from mint_litellm.endpoint.routes import KIT_KEY_ROUTES

    seen = {}

    async def open_(self, key_token, request_id, server, tool, reason, note):
        seen["open"] = (key_token, request_id, server, tool, reason, note)
        if server == "nope":
            raise RuntimeError("MINT-NOTFOUND: no such server")
        return request_id if server == "demo" else UUID(int=9)

    async def cancel(self, key_token, request_id):
        seen["cancel"] = (key_token, request_id)
        return request_id == UUID(int=3)

    async def mine(self, key_token):
        return [{"id": UUID(int=3), "server_id": "demo", "tool": "t", "reason_code": "DENIED",
                 "status": "open", "resolution": None, "decision_note": None,
                 "created_at": UNTIL, "decided_at": None}]

    async def live(self, key_token):
        return set()  # demo 서버의 승인이 모두 끝났다

    async def approved(self, instance_id, key_token):
        return [{"id": UUID(int=1), "server_id": "demo", "status": "decided",
                 "decision": "approved", "reason": None, "created_at": UNTIL}]

    for name, fn in (("endpoint_access_open", open_), ("endpoint_access_cancel", cancel),
                     ("endpoint_access_mine", mine), ("endpoint_live_servers", live),
                     ("endpoint_my_intakes", approved)):
        monkeypatch.setattr(FakeDatabase, name, fn, raising=False)
    client, _ = build(tmp_path)
    body = {"request_id": str(UUID(int=3)), "server": "demo", "tool": "t", "reason_code": "DENIED",
            "note": "정리"}
    answer = post(client, ACCESS, body)
    assert answer.status_code == 201 and answer.json() == {"id": str(UUID(int=3)), "reused": False}
    assert seen["open"] == (KEY, UUID(int=3), "demo", "t", "DENIED", "정리")
    assert post(client, ACCESS, {**body, "server": "other"}).json()["reused"] is True
    assert post(client, ACCESS, {**body, "server": "nope"}).status_code == 404
    assert post(client, ACCESS, {**body, "reason_code": "MASTER_KEY"}).status_code == 422
    assert post(client, ACCESS, {**body, "user_id": "u9"}).status_code == 422
    assert post(client, ACCESS + f"/{UUID(int=3)}/cancel", None).status_code == 200
    assert post(client, ACCESS + f"/{UUID(int=4)}/cancel", None).status_code == 404
    me = client.get(ME, headers=KEY_HEADER).json()
    assert me["access_requests"][0]["status"] == "open" and me["access_requests"][0]["tool"] == "t"
    assert me["intakes"][0]["stage"] == "ended"  # QA-BUG-009
    assert ACCESS in KIT_KEY_ROUTES and ACCESS + "/*" in KIT_KEY_ROUTES
