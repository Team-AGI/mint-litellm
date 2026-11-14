"""LiteLLM 키 차단 제안 명령(``key-block list|show|approve|reject|unblock``).

차단과 해제는 작업 실행기가 LiteLLM에 쓰고 결과를 다시 읽어 확인한다. 이 명령은 승인·거절·해제
요청을 기록하고, 기본으로 그 결과를 기다린다(``--no-wait``로 끈다).
"""

import time
from typing import Any

from mint_litellm.control import key_block
from mint_litellm.control.db.connection import fetchone
from mint_litellm.types.cli_commands import ADMIN_ONLY, ALL_ROLES, APPROVER_UP, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        path=("key-block", "list"), summary="LiteLLM 키 차단 제안 목록을 보인다.", roles=ALL_ROLES
    ),
    CliCommand(
        path=("key-block", "show"),
        summary="차단 제안의 증거 요약·영향 범위·현재 상태를 보인다(비밀 값은 없다).",
        roles=ALL_ROLES,
    ),
    CliCommand(
        path=("key-block", "approve"),
        summary="차단 제안을 승인한다. 승인 시점에 LiteLLM의 현재 상태를 다시 읽고, 작업 실행기가 "
        "LiteLLM 차단을 걸고 결과를 확인한다. 팀 전체 차단은 `--team`으로 따로 고른다.",
        roles=APPROVER_UP,
        litellm_reads=("/key/info", "/team/info"),
        events=(EventKind.KEY_BLOCK_APPROVED, EventKind.KEY_BLOCK_APPLIED,
                EventKind.KEY_BLOCK_FAILED),
    ),
    CliCommand(
        path=("key-block", "reject"),
        summary="차단 제안을 거절한다.",
        roles=APPROVER_UP,
        events=(EventKind.KEY_BLOCK_REJECTED,),
    ),
    CliCommand(
        path=("key-block", "unblock"),
        summary="MINT가 제안해 건 차단을 푼다(자동 해제는 없다). 차단 뒤 LiteLLM에서 대상이 바뀐 "
        "것으로 보이면 경고하며 `--acknowledge`로 확인해야 한다.",
        roles=ADMIN_ONLY,
        litellm_reads=("/key/info", "/team/info"),
        events=(EventKind.KEY_BLOCK_UNBLOCK_REQUESTED, EventKind.KEY_BLOCK_UNBLOCKED),
    ),
)

_WAIT = [(("--no-wait",), {"action": "store_true", "help": "요청만 하고 결과를 기다리지 않는다"})]
ARGUMENTS: dict[str, list[Any]] = {
    "key-block list": [(("--status",), {"help": "상태로 거른다(proposed·approved·applied …)"})],
    "key-block show": [(("proposal_id",), {"help": "제안 식별자(끝 8자리도 된다)"})],
    "key-block approve": [
        (("proposal_id",), {"help": "제안 식별자(끝 8자리도 된다)"}),
        (("--team",), {"action": "store_true", "help": "키 대신 팀 전체를 차단한다"}),
        (("--reason",), {"default": "", "help": "승인 사유"}),
        (("--version",), {"type": int, "help": "읽은 상태 버전(다르면 거부)"}),
        *_WAIT,
    ],
    "key-block reject": [
        (("proposal_id",), {"help": "제안 식별자(끝 8자리도 된다)"}),
        (("--reason",), {"default": "", "help": "거절 사유"}),
        (("--version",), {"type": int, "help": "읽은 상태 버전(다르면 거부)"}),
    ],
    "key-block unblock": [
        (("proposal_id",), {"help": "제안 식별자(끝 8자리도 된다)"}),
        (("--reason",), {"required": True, "help": "해제 사유"}),
        (("--acknowledge",), {"action": "store_true",
                              "help": "차단 뒤 바뀐 것으로 보이는 경고를 확인했다"}),
        (("--version",), {"type": int, "help": "읽은 상태 버전(다르면 거부)"}),
        *_WAIT,
    ],
}
WAIT_SECONDS = 60


def _public(row: dict) -> dict:
    keep = ("id", "status", "signal", "key_alias", "user_id", "team_id", "team_key_count",
            "team_member_count", "scope", "evidence", "blocked_at_proposal", "expires_at",
            "created_at", "state_version", "decided_by", "decided_at", "decision_reason",
            "mint_blocked", "applied_at", "last_error", "unblocked_by", "unblocked_at")
    return {k: row[k] for k in keep}


def _list(run) -> None:
    rows = key_block.listing(run.conn, run.cfg.instance_id, run.args.status)
    run.data["proposals"] = [_public(r) for r in rows]
    if not rows:
        run.say("차단 제안이 없습니다.")
    for r in rows:
        run.say(f"{r['id']}  {r['status']}  {r['signal']}  키 {r['key_alias'] or '—'}  "
                f"만료 {r['expires_at']:%Y-%m-%d %H:%M}")


def _show(run) -> None:
    row = key_block.show(run.conn, run.cfg.instance_id, run.args.proposal_id)
    run.data.update(_public(row))
    run.say(f"{row['id']}  {row['status']}  {row['signal']}")
    run.say(f"키 {row['key_alias'] or '—'}  사용자 {row['user_id'] or '—'}  "
            f"팀 {row['team_id'] or '—'}(키 {row['team_key_count']}개, 구성원 "
            f"{row['team_member_count']}명)")
    run.say(f"증거 {row['evidence']}")
    run.say(f"만료 {row['expires_at']:%Y-%m-%d %H:%M}  상태 버전 {row['state_version']}")


def _wait(run, proposal: str, done: tuple[str, ...]) -> None:
    run.conn.commit()
    if run.args.no_wait:
        run.say("요청을 기록했습니다. `key-block show`로 결과를 확인하십시오.")
        return
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        row = fetchone(
            run.conn,
            "SELECT status, last_error FROM mint.key_block_proposals"
            " WHERE instance_id = %s AND id = %s",
            (run.cfg.instance_id, proposal),
        )
        run.conn.commit()
        if row["status"] in done:
            if row["status"] == "failed":
                run.failure = f"LiteLLM 차단에 실패했습니다: {row['last_error']}"
            else:
                run.say(f"완료했습니다({row['status']}).")
            return
        time.sleep(1)
    run.say("작업 실행기가 아직 처리하지 않았습니다. 잠시 뒤 `key-block show`로 확인하십시오.")


def _approve(run) -> None:
    a = run.args
    result = key_block.approve(
        run.context(), run.litellm(), a.proposal_id, scope="team" if a.team else "key",
        reason=a.reason, expected_version=a.version,
    )
    run.data.update(result)
    run.say(f"승인했습니다({result['status']}).")
    if result["status"] == "approved":
        _wait(run, a.proposal_id, ("applied", "failed"))


def _reject(run) -> None:
    a = run.args
    run.data.update(key_block.reject(run.context(), a.proposal_id, reason=a.reason,
                                     expected_version=a.version))
    run.say("거절했습니다.")


def _unblock(run) -> None:
    a = run.args
    result = key_block.request_unblock(
        run.context(), run.litellm(), a.proposal_id, reason=a.reason, acknowledge=a.acknowledge,
        expected_version=a.version,
    )
    run.data.update(result)
    if result["status"] == "unblocking":
        run.say("해제를 요청했습니다.")
        _wait(run, a.proposal_id, ("unblocked", "applied"))
    else:
        run.say("LiteLLM에서 이미 풀려 있어 기록만 남겼습니다.")


HANDLERS = {
    "key-block list": _list, "key-block show": _show, "key-block approve": _approve,
    "key-block reject": _reject, "key-block unblock": _unblock,
}
