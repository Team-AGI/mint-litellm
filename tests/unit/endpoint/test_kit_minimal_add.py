"""입력 최소 신청(대상+목적)과 승인 즉시 사용(자동 받기·단계 표시)."""

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
    assert body == {"request_id": RID, "server_id": "notes-example-com", "transport": "http",
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
        return "https://mcp.example.com/mcp" if "대상" in question else "문서 조회"

    kit_module.interactive_add(None, gateway, tmp_path, None, read=read, key=lambda: "enter")
    assert [q.split("(")[0].strip() for q in asked] == ["대상", "목적"]
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
