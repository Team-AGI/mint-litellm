"""사람이 확인하는 정책의 증빙 명령과 이용 관계 종료 완료. 1단계 명령 표는 건드리지 않는다.

인증과 역할 확인은 다른 명령과 같다(운영자 토큰). ``cli.py``가 이 표를 파서와 실행 경로에 붙인다.
"""

import argparse
from datetime import UTC, datetime
from typing import Any

from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import relations as relation_service
from mint_litellm.types.cli_commands import ADMIN_ONLY, ALL_ROLES, APPROVER_UP, CliCommand
from mint_litellm.types.events import EventKind

_KINDS = ", ".join(f"{k.key}({k.label})" for k in evidence_service.KINDS.values())

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        path=("evidence", "attach"),
        summary="정책이 요구하는 증빙을 대상에 붙인다. 필수 증빙이 없거나 기한이 지나면 "
        "승인·재승인·관계 종료 완료가 거절된다. 증빙을 붙이면 같은 증빙의 열린 경보가 닫힌다.",
        roles=APPROVER_UP,
        events=(EventKind.EVIDENCE_ATTACHED,),
    ),
    CliCommand(
        path=("evidence", "show"),
        summary="대상에 붙일 수 있는 증빙 종류마다 현재 상태(유효·만료 임박·만료·없음)를 보인다.",
        roles=ALL_ROLES,
    ),
    CliCommand(
        path=("relation", "finish"),
        summary="종료 중인 이용 관계를 종료됨으로 닫는다. 자료 삭제·반환 증빙이 있어야 한다.",
        roles=ADMIN_ONLY,
        events=(EventKind.RELATION_TERMINATED,),
    ),
)


def _when(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"날짜·시각 형식이 올바르지 않습니다: {text}") from None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


ARGUMENTS: dict[str, list[Any]] = {
    "evidence attach": [
        (("kind",), {"choices": list(evidence_service.KINDS), "help": f"증빙 종류: {_KINDS}"}),
        (("subject_id",), {"help": "대상 식별자(신청·서버·이용 관계, 종류가 정한다)"}),
        (("--summary",), {"required": True, "help": "확인한 내용 요약(해당 없음이면 그 사유)"}),
        (("--ref",), {"help": "증빙 문서의 위치"}),
        (("--sha256",), {"help": "증빙 문서의 해시값(소문자 16진 64자)"}),
        (("--valid-until",), {"type": _when, "help": "유효 기한(기본은 종류별 기간)"}),
        (("--not-applicable",), {"action": "store_true", "help": "해당 없음으로 확인"}),
    ],
    "evidence show": [
        (("subject_kind",), {"choices": ["intake", "server", "relation"], "help": "대상 구분"}),
        (("subject_id",), {"help": "대상 식별자"}),
    ],
    "relation finish": [(("relation",), {"help": "이용 관계 식별자"})],
}

_STATE = {"valid": "유효", "not_applicable": "해당 없음", "expiring": "만료 임박",
          "expired": "만료", "missing": "없음"}


def _attach(run) -> None:
    a = run.args
    evidence_id = evidence_service.attach(
        run.context(), a.kind, a.subject_id, summary=a.summary, ref=a.ref, sha256=a.sha256,
        valid_until=a.valid_until, not_applicable=a.not_applicable,
    )
    run.data["id"] = evidence_id
    run.say(evidence_id)


def _show(run) -> None:
    items = evidence_service.show(run.context(), run.args.subject_kind, run.args.subject_id)
    run.data["evidence"] = [
        {"kind": e["key"], "policy": e["policy"], "gate": e["gate"], "state": e["state"],
         "valid_until": e["row"]["valid_until"].isoformat()
         if e["row"] and e["row"]["valid_until"] else None}
        for e in items
    ]
    for e in items:
        until = e["row"]["valid_until"] if e["row"] else None
        run.say(f"{e['key']}\t{e['label']}\t{_STATE[e['state']]}\t"
                f"{until.isoformat() if until else '-'}")


HANDLERS = {
    "evidence attach": _attach,
    "evidence show": _show,
    "relation finish": lambda run: relation_service.finish(run.context(), run.args.relation),
}
