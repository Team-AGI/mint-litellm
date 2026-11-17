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

    async def my_intakes(self, instance_id, key_token):
        return [{"id": UUID(int=1), "server_id": "demo", "status": "received", "decision": None,
                 "reason": None, "created_at": UNTIL}]

    async def submit(self, key_token, request_id, payload):
        calls["submit"].append((key_token, request_id, payload))
        if isinstance(calls.get("raise"), Exception):
            raise calls["raise"]
        return UUID(int=2)

    for name, fn in (("endpoint_scope", endpoint_scope), ("endpoint_my_intakes", my_intakes),
                     ("endpoint_submit_intake", submit)):
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
    assert answer["intakes"][0]["next"] == "wait"
    assert client.get(ME).status_code == 401
    assert client.get(ME, headers=HEADERS).json()["servers"] == []


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
