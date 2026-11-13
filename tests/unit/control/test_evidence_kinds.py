"""사람이 확인하는 증빙 종류 표와 상태 판정(데이터베이스 없이)."""

from datetime import UTC, datetime, timedelta

from mint_litellm import cli
from mint_litellm.control.services import evidence

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def row(days, result="confirmed"):
    return {"valid_until": None if days is None else NOW + timedelta(days=days), "result": result}


def test_state_follows_the_deadline():
    assert evidence.state_of(None, NOW) == "missing"
    assert evidence.state_of(row(-1), NOW) == "expired"
    assert evidence.state_of(row(3), NOW) == "expiring"
    assert evidence.state_of(row(30), NOW) == "valid"
    assert evidence.state_of(row(None), NOW) == "valid"
    assert evidence.state_of(row(30, "not_applicable"), NOW) == "not_applicable"


def test_every_kind_has_a_subject_a_gate_and_a_unique_label():
    kinds = list(evidence.KINDS.values())
    assert len({k.label for k in kinds}) == len(kinds) == 15
    assert {k.subject for k in kinds} == {"intake", "server", "relation"}
    gates = {"approve", "reapprove", "finish", "periodic", "unpinned", "exception", "retire"}
    assert {k.gate for k in kinds} == gates
    assert all(k.subject == "intake" for k in kinds if k.gate == "approve")
    assert all(k.subject == "relation" for k in kinds if k.gate == "finish")


def test_the_evidence_commands_are_reachable_from_the_command_line():
    parser = cli.build_parser()
    args = parser.parse_args(["evidence", "attach", "trial_call", "abc", "--summary", "확인"])
    assert args.command_name == "evidence attach" and args.not_applicable is False
    args = parser.parse_args(["relation", "finish", "rel-1"])
    assert args.command_name == "relation finish"
    assert {"evidence attach", "evidence show", "relation finish"} <= set(cli.COMMAND_INDEX)
