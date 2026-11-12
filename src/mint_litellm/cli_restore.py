"""2단계 봉인·내보내기·복원 명령. 1단계 명령 표(``COMMANDS``)는 건드리지 않고 따로 둔다.

인증과 역할 확인은 1단계 명령과 같다(운영자 토큰). ``cli.py``가 이 표를 파서와 실행 경로에 붙인다.
"""

import json
from pathlib import Path
from typing import Any

from mint_litellm.control import exports, seal
from mint_litellm.control import operators as operator_module
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.services import restore as restore_service
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.restore import files
from mint_litellm.types.cli_commands import ADMIN_ONLY, ALL_ROLES, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(path=("seal", "verify"), summary="봉인 연쇄를 처음부터 다시 계산해 검증한다",
               roles=ALL_ROLES),
    CliCommand(path=("export", "status"), summary="내보내기 파일과 키 교체 상태를 보여 준다",
               roles=ALL_ROLES),
    CliCommand(path=("restore", "check"), summary="내보내기 파일의 부정 상태와 DB를 비교한다",
               roles=ADMIN_ONLY),
    CliCommand(path=("restore", "attest"),
               summary="누락된 부정 상태를 다시 적용하고 세대를 올려 복원을 확인한다",
               roles=ADMIN_ONLY, events=(EventKind.RESTORE_ATTESTED,)),
    CliCommand(path=("restore", "accept-stale"),
               summary="파일이 없거나 검증되지 않을 때 DB 기준 새 파일로 해제한다(admin 2인)",
               roles=ADMIN_ONLY, events=(EventKind.RESTORE_STALE_ACCEPTED,)),
)

_REASON = (("--reason",), {"required": True, "help": "사유"})
ARGUMENTS: dict[str, list[Any]] = {
    "seal verify": [(("--from",), {"dest": "from_seq", "type": int}),
                    (("--to",), {"dest": "to_seq", "type": int})],
    "restore attest": [
        _REASON,
        (("--second-approver",), {"help": "봉인 앵커만 어긋난 경우의 다른 사용자 admin 토큰"}),
    ],
    "restore accept-stale": [
        _REASON,
        (("--second-approver",), {"help": "다른 사용자의 admin 토큰(@파일 가능)"}),
    ],
}


def _settings(run) -> Stage2Settings:
    return Stage2Settings.from_env(run.environ)


def _seal_verify(run) -> None:
    settings = _settings(run)
    checkpoint = None
    try:
        latest = files.read_verified(
            files.latest_path(settings.export_dir, run.cfg.instance_id), exports.keys(settings))
        if latest.get("to_seal_seq") is not None:
            checkpoint = (latest["to_seal_seq"], latest["tail_hash"])
    except (FileNotFoundError, files.ExportUnverified):
        pass
    result = seal.verify(run.conn, run.cfg.instance_id, run.args.from_seq, run.args.to_seq,
                         checkpoint, exports.keys(settings))
    run.data.update(result)
    run.say(f"봉인 배치 {result['batches']}개, 행 {result['rows']}건 검사: "
            + ("이상 없음" if result["ok"] else "연쇄가 어긋났습니다"))
    for error in result["errors"]:
        run.say(f"  - {error}")
    if checkpoint is None:
        run.say("체크포인트 파일의 봉인 끝과는 대조하지 못했습니다(파일 없음).")
    if not result["ok"]:
        run.failure = "봉인 연쇄 검증에 실패했습니다."


def _recent_exports(conn, instance_id: str) -> list[dict]:
    rows = fetchall(
        conn,
        "SELECT kind, state_epoch, to_seal_seq, status, attempts, path, written_at"
        " FROM mint.exports WHERE instance_id = %s ORDER BY written_at DESC NULLS LAST,"
        " state_epoch DESC LIMIT 20",
        (instance_id,),
    )
    return json.loads(json.dumps(rows, default=str))


def _export_status(run) -> None:
    settings = _settings(run)
    iid = run.cfg.instance_id
    rows = _recent_exports(run.conn, iid)
    current = files.key_id(settings.export_hmac_key)
    state: dict[str, Any] = {"current_key_id": current, "exports": rows}
    try:
        keys = exports.keys(settings)
        latest = files.read_verified(files.latest_path(settings.export_dir, iid), keys)
        newest = files.newest_negative(settings.export_dir, iid)
        negative = None if newest is None else files.read_verified(newest, keys)
        state.update(latest_epoch=latest["state_epoch"], latest_written_at=latest["written_at"],
                     latest_key_id=latest["key_id"])
        state["previous_key_removable"] = latest["key_id"] == current and (
            negative is None or negative["key_id"] == current)
    except (FileNotFoundError, files.ExportUnverified) as error:
        state["error"] = type(error).__name__
    run.data.update(state)
    for row in rows[:5]:
        run.say(f"{row['kind']} 세대 {row['state_epoch']} {row['status']} {row['path']}")
    if "error" in state:
        run.say(f"latest.json을 읽지 못했습니다({state['error']}).")
    elif state["previous_key_removable"]:
        run.say("최신 파일이 모두 현재 키로 서명되었습니다. 옛 키(MINT_EXPORT_HMAC_KEY_PREVIOUS)를"
                " 빼도 됩니다.")
    elif settings.export_hmac_key_previous:
        run.say("아직 옛 키로 서명된 최신 파일이 있습니다. 다음 체크포인트 뒤에 다시 확인하십시오.")


def _restore_check(run) -> None:
    result = restore_service.check(run.conn, run.cfg.instance_id, _settings(run))
    run.data.update(json.loads(json.dumps(result, default=str)))
    if not result["readable"]:
        run.say(f"내보내기 파일을 읽을 수 없습니다({result['error']}). accept-stale로 해제합니다.")
        return
    run.say(f"파일 세대 {result['file_epoch']}, DB 세대 {result['db_epoch']}, "
            f"마지막 성공 전송 {result['last_export_at']}")
    run.say("봉인 앵커: " + ("일치" if result["anchor_ok"] else "DB와 다릅니다"))
    for item in result["items"]:
        run.say(f"  누락 {item['kind']}:{item['id']} ({item['problem']})")
    if not result["items"]:
        run.say("누락된 부정 상태가 없습니다.")
    run.say("이 시점 이후 활동이 있었던 서버(LiteLLM 권한 현재값을 점검하십시오): "
            + (", ".join(result["review_servers"]) or "없음"))


def _restore_attest(run) -> None:
    out = restore_service.attest(
        run.context(), _settings(run), run.args.reason, _second(run))
    run.data.update(out)
    run.say(f"복원을 확인했습니다. 세대 {out['db_epoch']}, 되돌린 항목 {len(out['reapplied'])}건. "
            "새 파일은 작업 실행기가 게시하면(최대 1분) 차단이 풀립니다.")


def _second(run):
    value = getattr(run.args, "second_approver", None)
    if not value:
        return None
    if value.startswith("@"):
        value = Path(value[1:]).read_text(encoding="utf-8").strip()
    return operator_module.authenticate(run.conn, run.cfg.instance_id, value)


def _restore_accept_stale(run) -> None:
    out = restore_service.accept_stale(
        run.context(), _settings(run), run.args.reason, _second(run))
    run.data.update(out)
    run.say(f"해제를 요청했습니다. 세대 {out['db_epoch']}. 새 파일은 작업 실행기가 게시합니다.")


HANDLERS = {
    "seal verify": _seal_verify,
    "export status": _export_status,
    "restore check": _restore_check,
    "restore attest": _restore_attest,
    "restore accept-stale": _restore_accept_stale,
}
