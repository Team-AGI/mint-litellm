"""내보내기 파일이 사라진 구성: 호출은 막히고 판정 사건이 원인 `export_missing`을 남긴다.

끝나면 파일을 되돌려 호출이 다시 허용되는 것까지 확인한다(다른 시험에 상태를 남기지 않는다).
"""

import pytest
import support
from test_acceptance_core import code_of

LATEST = "/var/lib/mint/export/integration/latest.json"


def worker_sh(script: str) -> str:
    done = support.compose("exec", "-T", "worker", "sh", "-c", script)
    return done.stdout


@pytest.fixture
def approved(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    world.approve(subject, world.prepare(subject))
    return subject


def test_a_missing_latest_file_blocks_calls_and_names_the_cause(world, approved):
    support.wait_until(lambda: world.call(approved).allowed, timeout=120, interval=3, what="start")
    worker_sh(f"mv {LATEST} {LATEST}.held")
    try:
        blocked = support.wait_until(
            lambda: (lambda o: o if not o.allowed else None)(world.call(approved)),
            timeout=180,
            interval=3,
            what="calls blocked after latest.json disappeared",
        )
        assert blocked.status == 403, blocked.body
        assert blocked.code == code_of("ENFORCEMENT_UNVERIFIED"), blocked.body
        # 응답에는 원인을 싣지 않고, 판정 사건의 맥락 단계에 원인 코드가 남는다.
        assert "export_missing" not in blocked.body
        [event] = world.events(blocked.mark)
        stop = event["payload"]["stop"]
        assert (stop["reason_code"], stop["detail"]) == (
            "ENFORCEMENT_UNVERIFIED",
            "cause=export_missing",
        )
    finally:
        worker_sh(f"mv {LATEST}.held {LATEST}")
    support.wait_until(
        lambda: world.call(approved).allowed, timeout=180, interval=3, what="calls allowed again"
    )
