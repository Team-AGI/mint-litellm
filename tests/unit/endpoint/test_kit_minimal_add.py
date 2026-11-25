"""입력 최소 신청(대상+목적)과 승인 즉시 사용(자동 받기·단계 표시)."""

import io
import json
import types
import uuid

import pytest
from kit_loader import load
from test_kit_install import make_kit
from test_kit_pack import GOOD, FakeGateway, add_args, desired_item, pack_of

from mint_litellm.endpoint.decide import IntakeBody, IntakeRequest, RemoteIntakeBody

kit_module = load("mint_kit")
agent = load("mint_agent")
RID = "00000000-0000-4000-8000-000000000001"


def add(tmp_path, **kw):
    gateway, lines = FakeGateway(), []
    code = kit_module.run_add(add_args(**kw), tmp_path, gateway, out=lines.append)
    return code, gateway.sent, lines


def test_a_remote_address_alone_becomes_a_remote_request_the_server_model_accepts(tmp_path):
    code, sent, lines = add(
        tmp_path, name="https://mcp.notes.example.com/mcp", command=[], request_id=RID)
    assert code == 0 and len(sent) == 1
    body = sent[0]
    assert body == {"request_id": RID, "server_id": "notes_example_com", "transport": "http",
                    "url": "https://mcp.notes.example.com/mcp", "purpose": "p"}  # fmt: skip
    parsed = IntakeRequest.model_validate(body).root
    assert isinstance(parsed, RemoteIntakeBody)
    assert parsed.payload()["data_grade"] == "internal" and parsed.payload()["resources"] == []
    assert any("주소" in line for line in lines)


def test_a_name_and_an_address_make_a_remote_request_and_sse_is_read_from_the_path(tmp_path):
    code, sent, _ = add(tmp_path, name="docs", command=["https://a.example.com/sse"])
    assert code == 0 and sent[0]["server_id"] == "docs" and sent[0]["transport"] == "sse"


@pytest.mark.parametrize(
    ("url", "text"),
    [("http://a.example.com/mcp", "https"), ("https://a.example.com:8080/mcp", "포트 8080"),
     ("https://u:p@a.example.com/mcp", "계정"), ("https://a.example.com/mcp?x=1", "쿼리")],
)
def test_an_address_that_breaks_the_rules_is_refused_in_words_before_sending(
    tmp_path, url, text
):
    code, sent, lines = add(tmp_path, name=url, command=[])
    assert code == 2 and sent == [] and text in lines[-1]


def test_the_server_refuses_what_the_kit_would_not_send():
    base = {"request_id": RID, "server_id": "docs", "purpose": "p"}
    for url in ("http://a.com/x", "https://u:p@a.com/", "https://a.com/x?y=1", "https://a.com/#z"):
        with pytest.raises(ValueError):
            IntakeRequest.model_validate({**base, "url": url})
    with pytest.raises(ValueError):  # 모르는 필드는 거부
        IntakeRequest.model_validate({**base, "url": "https://a.com/x", "user_id": "u"})


def test_a_local_request_still_validates_against_the_local_model(tmp_path):
    code, sent, _ = add(tmp_path)
    assert code == 0
    assert isinstance(IntakeRequest.model_validate({**sent[0], "request_id": RID}).root, IntakeBody)


def test_the_server_name_comes_from_the_command_and_the_network_from_its_addresses(tmp_path):
    code, sent, lines = add(
        tmp_path, name="uvx", command=["demo==1.0", "--api", "https://api.example.com/v1"],
        network=None)
    body = sent[0]
    assert code == 0 and body["server_id"] == "demo" and body["data_grade"] == "internal"
    assert body["network"] == "hosts" and body["allowed_hosts"] == ["api.example.com:443"]
    assert any(line.startswith("네트워크") and "api.example.com" in line for line in lines)


def test_the_screen_prompt_takes_one_target_and_the_purpose(tmp_path):
    asked, gateway = [], FakeGateway()

    def read(question):
        asked.append(question)
        return "https://mcp.example.com/mcp" if "주소" in question else "문서 조회"

    kit_module.interactive_add(None, gateway, tmp_path, None, read=read, key=lambda: "enter")
    assert [q.split("(")[0].strip() for q in asked] == ["주소 또는 실행 명령", "목적"]
    assert gateway.sent[0]["url"] == "https://mcp.example.com/mcp"
    assert gateway.sent[0]["purpose"] == "문서 조회"


def test_the_remote_payload_matches_what_the_database_function_checks():
    body = RemoteIntakeBody(request_id=uuid.UUID(RID), server_id="d", url="https://a.com/m",
                            purpose="x")
    payload = body.payload()
    contract = json.loads(payload["contract"])
    assert contract["url"] == payload["url"] and contract["auth_type"] == "none"
    assert contract["oauth_scopes"] == [] and payload["provider"] == "a.com"


# --- 승인 즉시 사용 ----------------------------------------------------------------------------


def test_the_reporter_fetches_an_approved_pack_by_itself_and_records_a_failure(
    tmp_path, folder, reports, monkeypatch
):
    kit = make_kit(folder, tmp_path, managed=True)
    env = type(kit).auto_fetch.__globals__
    mod = types.SimpleNamespace(**env)
    state = kit.install()
    kit.config.update(decide_url="https://gw.example.com", key="k")
    digest, blobs = pack_of(GOOD)
    item = desired_item("s", digest)
    kit.refresh(state, [item])
    kit.apply_permits(state, [item], set())
    monkeypatch.setitem(env, "fetch_pack", lambda g, n, d, progress=None: (_ for _ in ()
                        ).throw(mod.PackError("받지 못했습니다")))
    assert kit.auto_fetch(state, [item], set()) == []
    contracts, permits = kit.local_contracts(), kit.local_permits()
    now = 0
    staged = kit.home / ".cache/mint/packs"
    assert mod.pack_state("s", contracts["s"], kit.programs, staged, permits, now) in (
        mod.S_NEED, mod.S_EXPIRED)
    assert kit.pack_errors()["s"]["reason"] == "받지 못했습니다"
    monkeypatch.setitem(env, "fetch_pack", lambda g, n, d, progress=None: blobs)
    assert kit.auto_fetch(state, [item], set()) == ["s"]
    assert kit.pack_errors() == {}
    folder_ = kit.programs / "packs" / digest[:16]
    assert mod.ready_status(folder_, digest) == "ok"
    # 목록은 검증 기록을 읽어 파일을 다시 해시하지 않는다. 바뀌면 다시 전체 검증한다.
    assert kit.auto_fetch(state, [item], set()) == []
    calls = []
    real = mod.sha256_file
    monkeypatch.setitem(env, "sha256_file", lambda p: calls.append(p) or real(p))
    record = kit.programs / mod.PACK_VERIFIED
    for _ in range(3):
        assert mod.ready_cached(folder_, digest, record) == "ok"
    assert calls == []
    (folder_ / "evil.py").write_text("x")
    assert mod.ready_cached(folder_, digest, record) == "bad" and calls


def test_a_prepared_pack_is_not_usable_until_the_runner_has_started_it(tmp_path):
    home = tmp_path
    assert kit_module.server_evidence(home, "s") == [False, False, False]
    base = home / ".cache/mint"
    (base / "launched").mkdir(parents=True)
    (base / "launched" / "s-1.json").write_text(json.dumps({"server": "s", "pid": 1}))
    (base / "launched" / "other-2.json").write_text(json.dumps({"server": "other"}))
    assert kit_module.server_evidence(home, "s") == [True, False, False]
    (base / "tools").mkdir()
    (base / "tools" / "s.json").write_text(json.dumps({"server": "s", "tools": []}))
    (base / "called").mkdir()
    (base / "called" / "s").write_text("")
    assert kit_module.server_evidence(home, "s") == [True, True, True]
    assert kit_module.server_evidence(home, "other") == [True, False, False]


SHA = "e" * 40


def repo_fetch(files):
    def fetch(url):
        return files[url]
    return fetch


def test_a_repository_address_becomes_a_commit_pinned_local_request(tmp_path, monkeypatch):
    api = "https://api.github.com/repos/o/ghidra-mcp"
    raw = f"https://raw.githubusercontent.com/o/ghidra-mcp/{SHA}/"
    files = {api: b'{"default_branch": "main"}', f"{api}/commits/main": json.dumps(
        {"sha": SHA}).encode(), raw + "pyproject.toml": b'[project.scripts]\ngm = "g:main"\n'}
    real = kit_module.repo_command
    monkeypatch.setattr(kit_module, "repo_command", lambda url: real(url, repo_fetch(files)))
    code, sent, _ = add(tmp_path, name="https://github.com/o/ghidra-mcp", command=[],
                        request_id=RID)
    assert code == 0 and len(sent) == 1
    body = sent[0]
    assert body["server_id"] == "ghidra_mcp"
    assert body["spec"] == {"index": "git", "git": "https://github.com/o/ghidra-mcp",
                            "name": "ghidra-mcp", "version": SHA, "extras": [],
                            "command": "gm", "argv": []}
    assert isinstance(IntakeRequest.model_validate({**body, "request_id": RID}).root, IntakeBody)


def test_a_repository_without_a_script_is_refused_in_words(tmp_path, monkeypatch):
    def fetch(url):
        if url.endswith("pyproject.toml") or url.endswith("package.json"):
            raise kit_module.urllib.error.HTTPError(url, 404, "nf", {}, None)
        return b'{"default_branch": "main", "sha": "' + SHA.encode() + b'"}'

    real = kit_module.repo_command
    monkeypatch.setattr(kit_module, "repo_command", lambda url: real(url, fetch))
    code, sent, lines = add(tmp_path, name="https://github.com/o/r", command=[])
    assert code == 2 and sent == [] and "실행 명령을 찾지 못했습니다" in lines[-1]


def test_a_pinned_git_command_is_accepted_and_an_unpinned_one_is_not(tmp_path):
    code, sent, _ = add(tmp_path, name="gm", command=[
        "uvx", "--from", f"git+https://github.com/o/ghidra-mcp@{SHA}", "gm", "--x"])
    assert code == 0 and sent[0]["spec"]["argv"] == ["--x"]
    code, sent, _ = add(tmp_path, name="gm", command=[
        "uvx", "--from", "git+https://github.com/o/ghidra-mcp@main", "gm"])
    assert code == 2 and sent == []
    spec = {"index": "git", "name": "x", "version": "main", "command": "x",
            "git": "https://github.com/o/x"}
    with pytest.raises(ValueError):
        IntakeRequest.model_validate({"request_id": RID, "server_id": "x", "spec": spec,
                                      "purpose": "p", "data_grade": "internal"})


def test_new_request_is_a_three_step_screen_that_previews_then_submits_and_esc_cancels(tmp_path):
    model = {"connected": True, "servers": [], "intakes": [], "found": []}
    form = {"step": 1, "focus": 0, "values": ["https://mcp.example.com/mcp", "문서 조회"],
            "error": "", "ok": False, "preview": [], "result": [], "request_id": RID}
    first = "\n".join(kit_module.render_intake(model, form, 80, 24))
    for text in ("새 도입 신청", "주소 또는 실행 명령", "목적", "예)", "Enter  다음", "Esc  취소"):
        assert text in first
    gateway = FakeGateway()
    kit_module.intake_preview(form, gateway, tmp_path, submit=False)
    assert gateway.sent == [] and form["step"] == 2
    second = "\n".join(kit_module.render_intake(model, form, 80, 24))
    shown = ("2/3 확인", "종류", "원격", "이름", "주소", "Enter  제출", "e  고치기", "Esc  취소")
    for text in shown:
        assert text in second
    print(first, second, sep="\n")

    def keys(typed):
        it = iter(typed)
        return lambda text=False: next(it)

    out = io.StringIO()
    typed = [*"https://mcp.example.com/mcp", "enter", *"문서", "enter", "esc"]
    assert "취소" in kit_module.intake_screen(model, gateway, tmp_path, keys(typed), out)
    assert gateway.sent == []  # Esc는 보내지 않는다
    typed = [*"https://mcp.example.com/mcp", "enter", *"문서", "enter", "enter", "x"]
    assert "신청 번호" in kit_module.intake_screen(model, gateway, tmp_path, keys(typed), out)
    assert gateway.sent[0]["url"] == "https://mcp.example.com/mcp"
    assert gateway.sent[0]["purpose"] == "문서"
    bad = [*"http://a.example.com/x", "enter", *"p", "enter", "esc"]  # 잘못된 주소
    kit_module.intake_screen(model, gateway, tmp_path, keys(bad), out)
    assert "https" in out.getvalue() and len(gateway.sent) == 1
