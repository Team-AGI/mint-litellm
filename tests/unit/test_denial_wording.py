"""거부 안내의 첫 낱말로 정책 거부와 시스템 오류를 가른다(D-012). 전역 정지 판정 범위."""

from types import SimpleNamespace

import pytest

from mint_litellm.plugin.pipeline import halted
from mint_litellm.types.errors import Dependency, error_for_reason
from mint_litellm.types.reason_codes import PARAMETERIZED_REASONS, Reason

POLICY = ("[막힘]", "[승인 대기]")


@pytest.mark.parametrize("reason", list(Reason))
def test_every_refusal_starts_with_its_kind(reason):
    code = reason.value + ("_X" if reason in PARAMETERIZED_REASONS else "")
    if reason is Reason.CANCELLED:
        pytest.skip("취소는 안내 없이 끝난다")
    error = error_for_reason(code, "ref-1", Dependency.DB)
    guidance = error.guidance or ""
    if reason is Reason.DEPENDENCY_FAILURE:
        assert guidance.startswith("[일시 오류]") and "정책 거부가 아닙니다" in guidance
    else:
        assert guidance.startswith(POLICY), (reason, guidance)


def test_admin_blocks_and_policy_blocks_point_to_the_access_request():
    for reason in ("DENIED", "APPROVAL_ABSENT", "TOOL_NOT_IN_APPROVAL"):
        guidance = error_for_reason(reason, "ref-1").guidance
        assert "해결: 직원 화면 「내 MCP 서버」에서" in guidance


def test_a_global_halt_says_so_and_asks_not_to_retry():
    error = error_for_reason("GLOBAL_HALT", "ref-1")
    assert error.code == "MINT-GLOBAL-HALT" and not error.retry_safe
    assert "전역 정지" in error.guidance and "되풀이하지 마십시오" in error.guidance


def snapshot(scope, kind="remote"):
    return SimpleNamespace(
        settings=SimpleNamespace(halt_scope=scope), server=SimpleNamespace(identity_kind=kind)
    )


def test_halt_scopes_cover_all_calls_or_only_local_servers():
    assert halted(snapshot("all")) and halted(snapshot("all", "stdio"))
    assert halted(snapshot("local", "stdio")) and not halted(snapshot("local", "remote"))
    assert not halted(snapshot("freeze", "stdio")) and not halted(snapshot(None, "stdio"))
    assert not halted(SimpleNamespace(settings=None, server=None))
