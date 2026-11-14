"""백업·복원과 설정 이전 명령. 1단계 명령 표는 건드리지 않고 따로 둔다.

복원은 이미 있는 ``restore`` 묶음(부정 상태 확인)과 구별하려고 ``backup restore``로 둔다.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mint_litellm.control import backup, config_transfer
from mint_litellm.control.errors import ControlError
from mint_litellm.types.cli_commands import ADMIN_ONLY, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(path=("backup", "create"),
               summary="제어 평면 데이터베이스(mint 스키마)의 일관된 백업 파일을 만든다.",
               roles=ADMIN_ONLY, events=(EventKind.BACKUP_CREATED,)),
    CliCommand(path=("backup", "restore"),
               summary="백업 파일로 mint 스키마를 되돌린다(수준이 같을 때만, --yes 필요).",
               roles=ADMIN_ONLY, events=(EventKind.BACKUP_RESTORED,)),
    CliCommand(path=("config", "export"),
               summary="서버·승인·규칙·거부·허용 목록·역할·모드 설정을 비밀 없이 내보낸다.",
               roles=ADMIN_ONLY, events=(EventKind.CONFIG_EXPORTED,)),
    CliCommand(path=("config", "import"),
               summary="내보낸 설정을 이 환경에 가져온다(되풀이 가능, --dry-run은 차이만).",
               roles=ADMIN_ONLY, events=(EventKind.CONFIG_IMPORTED,)),
)

_FILE = (("file",), {"help": "파일 경로"})
ARGUMENTS: dict[str, list[Any]] = {
    "backup create": [_FILE, (("--format",), {
        "choices": ("auto", "pg_dump", "json"), "default": "auto",
        "help": "auto는 pg_dump가 있으면 그것을, 없으면 논리 내보내기(JSON)를 쓴다"})],
    "backup restore": [_FILE, (("--yes",), {"action": "store_true", "help": "되돌림을 확인한다"})],
    "config export": [_FILE],
    "config import": [_FILE, (("--dry-run",), {"action": "store_true",
                                               "help": "적용하지 않고 차이만 보인다"})],
}


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")


def _passphrase(run) -> str | None:
    return run.environ.get(backup.PASSPHRASE_ENV) or None


def _create(run) -> None:
    head = backup.create(run.cfg.require_database(), Path(run.args.file), run.cfg.instance_id,
                         passphrase=_passphrase(run), mode=run.args.format)
    shown = {k: head[k] for k in ("mode", "mint_version", "migration_level", "created_at",
                                  "encrypted", "body_sha256")}
    run.context().emit(EventKind.BACKUP_CREATED, _stamp(), 1,
                       {**shown, "file": os.path.basename(run.args.file)})
    run.data.update(file=run.args.file, **shown)
    run.say(f"백업을 만들었습니다: {run.args.file} ({head['mode']}, "
            f"{'암호화' if head['encrypted'] else '암호화 안 함'})")


def _restore(run) -> None:
    if not run.args.yes:
        raise ControlError("복원은 현재 제어 평면 데이터를 덮어씁니다. --yes로 확인하십시오.")
    head, body = backup.read(Path(run.args.file), _passphrase(run))
    backup.check_restorable(run.conn, head, run.cfg.instance_id)
    # 열린 트랜잭션이 행 잠금을 쥐고 있으면 복원이 기다리므로 먼저 끝낸다.
    run.conn.commit()
    url = run.environ.get(backup.RESTORE_URL_ENV) or run.cfg.require_database()
    backup.restore(url, head, body)
    run.context().emit(EventKind.BACKUP_RESTORED, _stamp(), 1,
                       {"file": os.path.basename(run.args.file), "mode": head["mode"],
                        "migration_level": head["migration_level"],
                        "created_at": head["created_at"]})
    run.data.update(file=run.args.file, restored_from=head["created_at"])
    run.say(f"{head['created_at']}의 백업으로 되돌렸습니다. 작업 실행기·콘솔을 다시 시작하십시오.")


def _export(run) -> None:
    doc = config_transfer.export_doc(run.conn, run.cfg.instance_id)
    path = Path(run.args.file)
    if path.exists():
        raise ControlError(f"{path}이(가) 이미 있습니다.")
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
                    newline="\n")
    counts = {k: len(v) for k, v in doc.items() if isinstance(v, list) and k != "refill"}
    run.context().emit(EventKind.CONFIG_EXPORTED, _stamp(), 1,
                       {"file": path.name, "counts": counts})
    run.data.update(file=run.args.file, counts=counts)
    run.say(f"설정을 내보냈습니다: {path} (비밀·토큰 없음). 대상 환경에서 다시 채울 것: "
            + ", ".join(doc["refill"]))


def _import(run) -> None:
    doc = json.loads(Path(run.args.file).read_text(encoding="utf-8"))
    ctx = run.context()
    if run.args.dry_run:
        mark = len(ctx.emitted)
        try:
            with run.conn.transaction():
                result = config_transfer.apply(ctx, doc, run.cfg.mode_ceiling)
                raise config_transfer.DryRun
        except config_transfer.DryRun:
            pass
        del ctx.emitted[mark:]
    else:
        result = config_transfer.apply(ctx, doc, run.cfg.mode_ceiling)
        ctx.emit(EventKind.CONFIG_IMPORTED, _stamp(), 1, {
            "file": os.path.basename(run.args.file), "source_instance": doc.get("instance_id"),
            "created": {k: v["created"] for k, v in result.items()
                        if isinstance(v, dict) and "created" in v},
            "skipped": len(result["skipped"])})
    run.data.update(dry_run=run.args.dry_run, result=result)
    prefix = "[시험 실행] " if run.args.dry_run else ""
    for section, r in result.items():
        if isinstance(r, dict) and "created" in r:
            run.say(f"{prefix}{section}: 새로 {r['created']}, 이미 있음 {r['present']}")
    if result["settings"]:
        run.say(f"{prefix}settings: {json.dumps(result['settings'], ensure_ascii=False)}")
    for s in result["skipped"]:
        run.say(f"건너뜀 {s['section']}: {s['reason']}")
    todo = result["todo"]
    for server_id in todo["servers_to_register"]:
        run.say(f"할 일: mint-litellm server register {server_id}")
    for op in todo["operators_to_add"]:
        run.say(f"할 일: mint-litellm operator add --name {op['name']} --role {op['role']}")
    if todo["approvals_to_grant"]:
        run.say(f"할 일: 승인 {todo['approvals_to_grant']}건은 가져오지 않습니다. 이 환경의 "
                "승인자가 mint-litellm approve로 직접 승인하십시오.")


HANDLERS = {"backup create": _create, "backup restore": _restore,
            "config export": _export, "config import": _import}
