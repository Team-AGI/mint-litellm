"""PC 명령 계층: 옛 이름 별칭(QA-CLI-001), 종료 코드(QA-CLI-002), --json, 비대화형."""

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from mint_litellm.endpoint.kit import mint_kit

ROWS = [
    {"name": "github_mcp", "kind": "묶음", "state": mint_kit.S_READY,
     "permit_until": "2026-12-01T09:00:00Z", "pack_sha256": "ab" * 32, "reason": ""},
    {"name": "fetch", "kind": "로컬", "state": mint_kit.S_NEED, "permit_until": None,
     "pack_sha256": None, "reason": ""},
]  # fmt: skip
INTAKES = [
    {"id": "3f2a9c1b-0000", "server_id": "docs_mcp", "status": "checking", "decision": None,
     "stage": "inspect", "next": "wait", "reason": None, "created_at": "2026-11-25T01:00:00Z"},
    {"id": "9d8e7f60-0000", "server_id": "old_mcp", "status": "decided", "decision": "approved",
     "stage": "approved", "next": "none", "reason": None, "created_at": "2026-11-20T01:00:00Z"},
]  # fmt: skip


class Gate:
    def __init__(self, status=200, servers=(), intakes=INTAKES):
        self.status = status
        self.me = {"servers": [{"server_id": s} for s in servers], "intakes": list(intakes)}
        self.sent = []

    def json(self, method, path, body=None):
        if method == "POST":
            self.sent.append(body)
            return 201, {"id": "new-1"}
        return self.status, self.me if self.status == 200 else None


@pytest.fixture
def world(tmp_path, monkeypatch):
    """설치된 PC 하나: 가짜 키트·모델·게이트웨이."""
    kit = SimpleNamespace(home=tmp_path, folder=tmp_path / "kit", harnesses=["claude"],
                          config={"decide_url": "https://gw.example/mint", "key": "k"})  # fmt: skip
    box = SimpleNamespace(gateway=Gate(), state={"mode": "user", "user": "kim"})
    monkeypatch.setattr(mint_kit, "open_installed",
                        lambda folder: (kit, box.state, box.gateway))  # fmt: skip

    def model(_kit, _state, gateway):
        status, me = gateway.json("GET", mint_kit.ME_PATH)
        return {"servers": [dict(r) for r in ROWS], "intakes": me["intakes"],
                "access_requests": mint_kit.access_rows(me)}

    monkeypatch.setattr(mint_kit, "build_model", model)
    monkeypatch.setattr(mint_kit.sys.stdin, "isatty", lambda: False)
    box.kit = kit
    return box


def run(capsys, *argv):
    code = mint_kit.main(list(argv))
    seen = capsys.readouterr()
    return code, seen.out, seen.err


# --- QA-CLI-001: 옛 명령이 같은 결과 -----------------------------------------------------------
def test_old_commands_parse_to_the_same_arguments_as_the_new_ones(monkeypatch):
    seen = []
    monkeypatch.setattr(mint_kit, "dispatch", lambda args: seen.append(vars(args)) or 0)
    pairs = [
        (["add", "https://x.example/mcp", "--purpose", "p"],
         ["server", "add", "https://x.example/mcp", "--purpose", "p"]),
        (["add", "n", "--purpose", "p", "--", "uvx", "a==1"],
         ["server", "add", "n", "--purpose", "p", "--", "uvx", "a==1"]),
        (["get", "gh"], ["server", "get", "gh"]),
        (["requests"], ["request", "list"]),
        (["inspect", "gh"], ["request", "inspect", "gh"]),
        (["relink", "https://gw/kit/c"], ["link", "https://gw/kit/c"]),
        (["--kit", "/k", "requests", "--json"], ["request", "list", "--kit", "/k", "--json"]),
    ]  # fmt: skip
    for old, new in pairs:
        assert mint_kit.cli_main(old) == 0
        assert mint_kit.cli_main(new) == 0
        assert seen[-2] == seen[-1], old


def test_app_rm_is_an_alias_of_remove(world, monkeypatch):
    calls = []
    monkeypatch.setattr(mint_kit, "run_app",
                        lambda args, *rest: calls.append((args.app_action, args.name)) or 0)
    assert mint_kit.cli_main(["app", "rm", "bot"]) == 0
    assert mint_kit.cli_main(["app", "remove", "bot"]) == 0
    assert calls == [("remove", "bot")] * 2


def test_doctor_is_check_and_the_old_check_still_works(monkeypatch):
    seen = []
    monkeypatch.setattr(mint_kit, "Kit", lambda *a, **k: seen.append(1) or (_ for _ in ()).throw(
        mint_kit.KitMissing("x")))  # fmt: skip
    for word in ("doctor", "check"):
        assert mint_kit.main([word, "--kit", "/none", "--user-level"]) == mint_kit.EXIT_LINK
    assert len(seen) == 2


# --- 목록·조회 ---------------------------------------------------------------------------------
def test_server_list_uses_the_web_words_and_the_json_has_one_object(world, capsys):
    code, out, _ = run(capsys, "server", "list")
    assert code == 0
    assert "github_mcp" in out and "사용 가능" in out and "준비 중" in out
    assert "mint server get fetch" in out  # 다음 할 일은 명령으로
    code, out, _ = run(capsys, "server", "list", "--json")
    doc = json.loads(out)
    assert [r["server_id"] for r in doc["servers"]] == ["github_mcp", "fetch"]
    assert doc["servers"][0]["state"] == "사용 가능"
    code, out, _ = run(capsys, "server", "list", "--json", "--fields", "server_id,state")
    assert json.loads(out)["servers"][1] == {"server_id": "fetch", "state": "준비 중"}


def test_an_unknown_json_field_lists_the_usable_ones(world, capsys):
    code, out, err = run(capsys, "server", "list", "--json", "--fields", "bogus")
    assert code == 2 and out == ""
    error = json.loads(err)["error"]
    assert error["code"] == "usage" and "server_id" in error["next"]
    assert error["message"] == "`bogus`는 없는 필드입니다."
    assert error["next"].startswith("쓸 수 있는 필드: server_id")


def test_server_show_and_a_missing_server(world, capsys):
    code, out, _ = run(capsys, "server", "show", "github_mcp")
    assert code == 0 and "사용 가능" in out and "도구" in out
    code, out, _ = run(capsys, "server", "show", "github_mcp", "--json")
    assert json.loads(out)["server_id"] == "github_mcp"
    code, out, err = run(capsys, "server", "show", "nope")
    assert code == 1
    assert err.splitlines() == [
        "오류: `nope` 서버가 내 서버 목록에 없습니다.", "다음: mint server list"]
    code, out, err = run(capsys, "server", "show", "docs_mcp")  # 신청 중인 서버
    assert code == 1 and "아직 승인되지 않았습니다" in err


def test_request_list_and_show_use_the_intake_words(world, capsys):
    code, out, _ = run(capsys, "request", "list")
    assert code == 0 and "3f2a9c1b" in out and "검사 중" in out and "승인됨" in out
    assert "wait" not in out and "none" not in out
    code, out, _ = run(capsys, "request", "list", "--json")
    assert [r["state"] for r in json.loads(out)["requests"]] == ["검사 중", "승인됨"]
    code, out, _ = run(capsys, "request", "show", "3f2a")
    assert code == 0 and "접수 > 묶음 준비 > 검사 중" in out
    code, out, err = run(capsys, "request", "show", "zzzz")
    assert code == 1 and err.splitlines()[1] == "다음: mint request list"
    code, out, _ = run(capsys, "requests")  # 옛 이름은 같은 표
    assert "3f2a9c1b" in out


def test_config_list_never_shows_the_key(world, capsys):
    code, out, _ = run(capsys, "config", "list")
    assert code == 0 and "https://gw.example/mint" in out and "있음" in out
    code, out, _ = run(capsys, "config", "list", "--json")
    doc = json.loads(out)
    assert doc["key"] == "present" and "k" != doc["key"] and set(doc) <= set(
        mint_kit.CONFIG_FIELDS)  # fmt: skip


# --- QA-CLI-002: 종료 코드 -----------------------------------------------------------------------
def test_exit_codes_match_the_documented_table(world, capsys, monkeypatch):
    docs = Path(mint_kit.__file__).parents[4].joinpath("docs/CLI.md").read_text(encoding="utf-8")
    for code, meaning in mint_kit.EXIT_TABLE:
        assert f"| {code} | {meaning} |" in docs
    assert run(capsys, "server", "list")[0] == mint_kit.EXIT_OK
    with pytest.raises(SystemExit) as stop:
        mint_kit.main(["server", "show"])
    assert stop.value.code == mint_kit.EXIT_USAGE
    capsys.readouterr()
    world.gateway = None  # 키 없음
    code, _, err = run(capsys, "server", "list")
    assert code == mint_kit.EXIT_LINK and err.splitlines()[1] == "다음: mint link <설치 주소>"
    world.gateway = Gate(status=403)  # 키 거절
    assert run(capsys, "request", "list")[0] == mint_kit.EXIT_LINK
    world.gateway = Gate(status=0)  # 게이트웨이 불통: 정책 거부가 아니다
    code, _, err = run(capsys, "server", "list")
    assert code == mint_kit.EXIT_FAIL and "정책 거부가 아닙니다" in err
    assert err.splitlines()[1] == "다음: mint doctor"
    world.gateway = Gate(servers=["github_mcp"])  # 승인 없는 서버 받기 = 정책 거부
    code, _, err = run(capsys, "server", "get", "other_mcp")
    assert code == mint_kit.EXIT_DENIED and err.startswith("[막힘] other_mcp")
    assert "mint request access other_mcp" in err
    code, _, err = run(capsys, "server", "get", "docs_mcp")  # 신청 중이면 거부가 아니다
    assert code == mint_kit.EXIT_FAIL


def test_app_run_returns_the_exit_code_of_the_command_it_ran(world, monkeypatch, capsys):
    monkeypatch.setattr(mint_kit, "run_app", lambda args, *rest: 127)
    assert run(capsys, "app", "run", "bot", "--", "nope")[0] == 127
    monkeypatch.setattr(mint_kit, "run_app", lambda args, *rest: 7)
    assert run(capsys, "app", "run", "bot", "--", "x")[0] == 7


class AccessGate(Gate):
    """권한 요청 경로를 흉내 내는 게이트웨이(보낸 본문과 취소 경로를 남긴다)."""

    def __init__(self, answer=(201, {"id": "a1b2c3d4-0000", "reused": False})):
        super().__init__()
        self.answer = answer
        self.me["access_requests"] = [
            {"id": "a1b2c3d4-0000", "server_id": "github_mcp", "tool": "delete_repo",
             "reason_code": "DENIED", "status": "open", "resolution": None,
             "decision_note": None, "created_at": "2026-11-25T02:00:00Z"},
            {"id": "e5f6a7b8-0000", "server_id": "docs_mcp", "tool": None,
             "reason_code": "APPROVAL_ABSENT", "status": "resolved", "resolution": "grant",
             "decision_note": None, "created_at": "2026-11-24T02:00:00Z"},
        ]  # fmt: skip
        self.paths = []

    def json(self, method, path, body=None):
        if method == "POST":
            self.paths.append(path)
            self.sent.append(body)
            return (200, {"cancelled": True}) if path.endswith("/cancel") else self.answer
        return super().json(method, path, body)


def test_access_opens_a_request_through_the_kit_key(world, capsys):
    world.gateway = AccessGate()
    ask = ["request", "access", "github_mcp", "delete_repo", "--reason", " 저장소 정리 "]
    code, out, _ = run(capsys, *ask)
    assert code == mint_kit.EXIT_OK and "권한 요청을 보냈습니다: github_mcp/delete_repo" in out
    body = world.gateway.sent[-1]
    assert world.gateway.paths[-1] == mint_kit.ACCESS_PATH
    assert body["server"] == "github_mcp" and body["tool"] == "delete_repo"
    assert body["note"] == "저장소 정리" and "user" not in body and len(body["request_id"]) == 36
    code, _, err = run(capsys, "request", "access", "github_mcp", "--json", "--reason", "x")
    assert code == 0 and "tool" not in world.gateway.sent[-1]
    world.gateway = AccessGate(answer=(201, {"id": "a1b2c3d4-0000", "reused": True}))
    code, out, _ = run(capsys, *ask)
    assert "이미 보낸 요청이 대기 중입니다" in out
    world.gateway = AccessGate(answer=(404, {"detail": "MINT-NOTFOUND: no such server"}))
    code, _, err = run(capsys, *ask)
    assert code == mint_kit.EXIT_FAIL and "서버가 조직에 없습니다" in err
    world.gateway = AccessGate(answer=(404, {"detail": "no such kit key"}))
    assert run(capsys, *ask)[0] == mint_kit.EXIT_LINK


def test_request_list_shows_access_requests_and_cancel_only_takes_open_ones(world, capsys):
    world.gateway = AccessGate()
    code, out, _ = run(capsys, "request", "list")
    assert "권한 요청" in out and "github_mcp/delete_repo" in out and "승인 대기" in out
    rows = json.loads(run(capsys, "request", "list", "--json")[1])["requests"]
    asks = [r for r in rows if r["kind"] == "권한 요청"]
    assert [r["state"] for r in asks] == ["승인 대기", "승인됨"]
    assert asks[1]["reason"] == "사용 허용됨" and asks[1]["next"] == "바로 쓸 수 있습니다"
    code, out, _ = run(capsys, "request", "cancel", "a1b2", "--yes")
    assert code == 0 and world.gateway.paths[-1] == mint_kit.ACCESS_PATH + "/a1b2c3d4-0000/cancel"
    code, _, err = run(capsys, "request", "cancel", "e5f6", "--yes")  # 이미 승인됨
    assert code == mint_kit.EXIT_FAIL and "이미 끝난 요청" in err
    code, _, err = run(capsys, "request", "cancel", "3f2a9c1b", "--yes")  # 서버 신청
    assert code == mint_kit.EXIT_FAIL and "「서버 신청」" in err


# --- 비대화형 ----------------------------------------------------------------------------------
def test_server_add_without_a_terminal_needs_a_purpose(world, capsys):
    code, out, err = run(capsys, "server", "add", "https://x.example/mcp")
    assert code == mint_kit.EXIT_USAGE and out == ""
    assert err.splitlines()[0].startswith("오류: 목적이 필요합니다")
    assert world.gateway.sent == []
    code, out, err = run(capsys, "server", "add", "https://x.example/mcp", "--yes")
    assert code == mint_kit.EXIT_USAGE and world.gateway.sent == []


def test_server_add_json_gives_the_request_and_the_old_add_matches(world, capsys):
    args = ["https://x.example/mcp", "--purpose", "문서 검색"]
    code, out, _ = run(capsys, "server", "add", *args, "--json")
    assert code == 0
    request = json.loads(out)["request"]
    assert request["id"] == "new-1" and request["server_id"] == "x_example"
    code, text, _ = run(capsys, "add", *args)  # 옛 이름: 같은 신청
    assert code == 0 and "신청했습니다" in text and "신청 번호 new-1" in text
    assert [b["url"] for b in world.gateway.sent] == ["https://x.example/mcp"] * 2


def test_the_screen_has_a_fourth_tab_named_my_requests():
    assert mint_kit.TABS[3] == "내 요청"
    model = {"access_requests": []}
    text = "\n".join(mint_kit.tab4_lines(model, {"cursor": 0}))
    assert "보낸 권한 요청이 없습니다" in text and "「내 요청」" in text
    model["access_requests"] = [{"server_id": "gh", "tool": "delete", "state": "대기"}]
    assert "gh/delete" in "\n".join(mint_kit.tab4_lines(model, {"cursor": 0}))


def test_help_text_lists_every_documented_noun_command():
    for line in ("server list|show", "request list|show", "request access", "request cancel",
                 "request inspect", "app new|list|remove|run|env|mcp", "config list"):  # fmt: skip
        assert line in mint_kit.HELP_TEXT
    assert re.search(r"종료 코드: 0 .* 4 정책 거부", mint_kit.HELP_TEXT)
