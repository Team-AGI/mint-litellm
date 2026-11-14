"""결과 통제: 업스트림 결과의 비밀·개인정보·지시문 표지가 실제 LiteLLM을 거쳐 가는 모습.

시험 서버의 ``leak`` 도구가 본문, 구조화된 결과, 또는 양쪽에 값을 싣는다. 승인 조건의
``response_scan``(mask, block, observe)별로 두 전송(``/mcp``, ``/mcp-rest/tools/call``)이
같은 결과를 받는지와, 응답 사건에 남는 필드를 확인한다. 집행 모드에서만 결과가 바뀐다.
"""

import json
import re
import time

import httpx
import pytest
import support
from scenario import litellm_config
from support import run

KINDS = ("secret", "pii", "injection", "clean")
WHERE = ("text", "structured", "both")
SCANS = ("mask", "block", "observe")
TRANSPORTS = ("mcp", "rest")
RAW = {
    "secret": "AKIAQWERTYUIOP234567",
    "pii": "900101-1234567",
    "injection": "Ignore all previous",
}
BLOCK_CODE = "MINT-OUTPUT-BLOCKED"


@pytest.fixture(scope="module")
def subjects(world, stack):
    """승인 조건의 response_scan별 주체."""
    world.mint.run("settings", "mode", "enforce")
    out = {}
    for scan in SCANS:
        subject = world.subject(("a",))
        relation = world.prepare(subject)
        world.approve(subject, relation, tools="leak", extra=("--response-scan", scan))
        out[scan] = subject
    return out


class View:
    """호출자가 받은 결과(전송과 무관한 형태)."""

    def __init__(self, text: str, structured, is_error: bool, status: int = 200):
        self.text, self.structured, self.is_error, self.status = text, structured, is_error, status

    @property
    def everything(self) -> str:
        return self.text + json.dumps(self.structured, ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            f"View({self.status}, error={self.is_error}, "
            f"text={self.text!r}, structured={self.structured!r})"
        )


def _view_of_result(result: dict) -> View:
    text = "".join(b.get("text", "") for b in result.get("content") or [])
    structured = result.get("structuredContent", result.get("structured_content"))
    return View(text, structured, bool(result.get("isError", result.get("is_error"))))


def call(transport: str, subject, kind: str, where: str) -> View:
    mark = support.marker()
    args = {"kind": kind, "where": where, "marker": mark}
    if transport == "mcp":
        result = run(support.call_tool(subject.key, "a", "leak", args))
        return _view_of_result(result.model_dump(by_alias=True))
    reply = support.rest_call(subject.key, "a", "leak", args, call_id=mark)
    if reply.status_code != 200:
        return View(reply.text, None, True, reply.status_code)
    body = reply.json()
    return _view_of_result(body if isinstance(body, dict) else {"content": body})


def response_event(world, subject, since) -> dict:
    """``since`` 이후 이 주체의 마지막 호출의 응답 사건 payload."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = world.query(
            "select r.payload from mint.events r join mint.events d "
            "on d.invocation_id = r.invocation_id and d.kind = 'decision_evaluated' "
            "where r.kind = 'call_response_received' and d.payload->'principal'->>'key_id' = %s "
            "and d.inserted_at >= %s order by r.inserted_at desc limit 1",
            (subject.key_id, since),
        )
        if rows:
            return rows[0]["payload"]
        time.sleep(0.5)
    raise AssertionError("응답 사건이 남지 않았다")


def expected(kind: str, where: str, scan: str, managed: bool = False) -> str:
    """pass | masked | blocked(집행 모드). 계약 관리가 아닌 서버의 지시문 표지는 기록만 한다."""
    if kind == "clean":
        return "pass"
    if kind == "injection":
        return "blocked" if managed else "pass"
    if scan == "observe":
        return "pass"
    if kind == "secret":
        if scan == "block" or where != "text":
            return "blocked"  # 구조화된 결과의 알려진 비밀은 가릴 수 없어 막는다
        return "masked"
    # 개인정보: 구조화된 결과에서는 경로만 남기고 통과한다. 본문은 모드대로.
    if where == "structured":
        return "pass"
    return "blocked" if scan == "block" else "masked"


CASES = [
    (k, w, s, t)
    for k in KINDS
    for w in WHERE
    for s in SCANS
    for t in TRANSPORTS
    if not (k == "clean" and (w != "text" or s != "mask"))
]


@pytest.mark.parametrize(("kind", "where", "scan", "transport"), CASES)
def test_result_reaches_the_caller_as_the_mode_says(world, subjects, kind, where, scan, transport):
    check_case(world, subjects[scan], kind, where, scan, transport, managed=False)


def check_case(world, subject, kind, where, scan, transport, *, managed):
    since = world.now()
    view = call(transport, subject, kind, where)
    want = expected(kind, where, scan, managed)
    raw = RAW.get(kind)
    if want == "pass":
        assert not view.is_error, view
        if kind != "clean":
            assert raw in view.everything, view
    else:
        assert raw not in view.everything, view
        if want == "blocked":
            assert BLOCK_CODE in view.everything, view
        else:
            assert "[MASKED:" in view.text, view
            # LiteLLM은 본문을 바꾼 결과에 구조화된 결과가 있으면 그것을 버리고 오류로 표시한다.
            if where == "both":
                assert view.is_error and view.structured is None, view

    event = response_event(world, subject, since)
    assert event["output_blocked"] is (want == "blocked"), event
    assert event["output_masked"] is (want == "masked"), event
    if kind == "clean":
        assert not event["output_findings"], event
    elif kind == "injection":
        assert "POL-E-04" in event["output_findings"], event
        assert managed or "POL-E-04" in event["unmanaged_findings"], event
    elif kind == "pii" and where == "structured":
        # 구조화된 결과의 개인정보는 경로만 남기고 통과한다(알려진 형식의 비밀만 센다).
        assert not event["output_findings"], event
    else:
        assert event["output_findings"], event
    if kind == "secret" or (kind == "pii" and where != "structured"):
        assert event["sensitive_findings"], event
    if where != "text" and kind in ("secret", "pii"):
        assert event["finding_paths"], event
    # 원문은 원장에 남지 않는다.
    assert not re.search(r"AKIA|900101|corp-mail", json.dumps(event)), event


def test_nothing_sensitive_is_left_in_the_litellm_logs(world, subjects):
    """원문은 호출자에게만 가고 LiteLLM 컨테이너 로그와 지출 기록에는 남지 않는다."""
    subject = subjects["mask"]
    for transport in TRANSPORTS:
        call(transport, subject, "secret", "text")
    for name in ("litellm1", "litellm2"):
        logs = support.compose("logs", "--no-color", name).stdout
        assert RAW["secret"] not in logs, name
    spend = httpx.get(
        support.url(support.LITELLM_PORTS[0], "/spend/logs"),
        headers=support.master_headers(),
        params={"user_id": subject.user_id},
        timeout=30,
    )
    assert RAW["secret"] not in spend.text


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_the_upstream_receives_exactly_the_arguments_that_were_judged(world, evidence, transport):
    """호출별 승인은 인자 지문에 묶인다. 승인이 통했다면 판정한 인자와 보낸 인자가 같고,
    업스트림이 받은 인자도 보낸 것과 같다."""
    evidence.positive_control()
    subject = world.subject(("a",))
    world.approve(subject, world.prepare(subject), extra=("--high-risk-tools", "echo"))
    mark = support.marker()
    sent = {"text": '한글 é "quote" person@corp-mail.kr', "marker": mark}
    world.call_approval(subject, sent)
    if transport == "mcp":
        run(support.call_tool(subject.key, "a", "echo", sent))
    else:
        reply = support.rest_call(subject.key, "a", "echo", sent, call_id=mark)
        assert reply.status_code == 200, reply.text
    got = httpx.get(f"{evidence.upstreams['a'].base}/counters", timeout=5).json()["received"]
    assert got[mark] == sent


def test_restart_with_unmanaged_scan_enforced_controls_the_first_call(world, subjects):
    """재기동 직후 첫 호출부터 결과가 통제되고(구조화 전용 포함), MINT_SCAN_UNMANAGED=enforce이면
    계약 관리가 아닌 서버의 지시문 표지도 막는다."""
    with litellm_config("./config/litellm.mint.yaml", env={"MINT_E_SCAN_UNMANAGED": "enforce"}):
        for transport in TRANSPORTS:
            for kind in ("injection", "secret"):
                for where in ("structured", "text"):
                    check_case(
                        world, subjects["mask"], kind, where, "mask", transport, managed=True
                    )
