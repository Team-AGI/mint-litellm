"""워커가 둘인 복제본에서, 목록에서 숨겨진 도구를 직접 호출해도 MINT가 판정한다.

LiteLLM은 워커마다 도구 경로표를 따로 갖고, 경로표에 없는 도구의 호출은 훅에 닿기 전에 「도구를
찾을 수 없다」(500)로 끝낸다. 경로표는 목록에 보인 도구만 채우므로, MINT가 목록에서 숨긴 도구를
한 번도 목록화하지 않은 워커가 받으면 판정도 사건도 남지 않았다. 호출은 복제본에 닿는 대로 워커를
가리지 않으므로, 같은 호출을 한꺼번에 여럿 보내 워커 모두에 닿게 한다. 도구는 아직 아무 워커도
목록화하지 않은 새 DB 서버의 것이다.
"""

import time
import uuid

import support
from scenario import db_server, decision
from test_acceptance_core import code_of

UPSTREAM_URL = "http://counting-proxy:8080/a/mcp"
CALLS = 12


def test_a_tool_hidden_from_the_list_is_judged_on_workers_that_never_listed_it(
    world, evidence, multiworker
):
    evidence.positive_control()
    alias = f"mw_{uuid.uuid4().hex[:8]}"
    # 서버는 지우지 않는다(등록된 서버가 레지스트리에서 사라지면 다음 기동 점검이 실패한다).
    server_id = db_server(alias, UPSTREAM_URL)
    support.TOOL_PREFIX[server_id] = alias
    support.UPSTREAM_OF[server_id] = "a"
    subject = world.subject((server_id,))
    world.approve(subject, world.prepare(subject, server_id, url=UPSTREAM_URL), tools="echo")

    outcomes = world.call_concurrently(
        subject, CALLS, server=server_id, tool="slow", port=multiworker
    )
    time.sleep(1)  # 업스트림 기록이 안정될 때까지
    for outcome in outcomes:
        assert outcome.status == 403, outcome.body
        assert outcome.code == code_of("TOOL_NOT_IN_APPROVAL"), outcome.body
        events = world.events(outcome.mark)
        assert len(events) == 1, outcome.body
        assert decision(events[0]) == ("block", "block", "TOOL_NOT_IN_APPROVAL")
        evidence.assert_calls(outcome.mark, 0, "a", settle=0)

    # 승인된 도구는 같은 복제본에서 그대로 허용된다.
    allowed = world.call(subject, server_id, "echo", port=multiworker)
    assert allowed.allowed, allowed.body
    events = world.events(allowed.mark)
    assert len(events) == 1 and decision(events[0])[:2] == ("allow", "allow")
    evidence.assert_calls(allowed.mark, 1, "a")
