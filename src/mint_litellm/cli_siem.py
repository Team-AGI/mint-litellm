"""SIEM 전달 대상 관리 명령(``siem add|list|remove|test``). 1단계 명령 표는 건드리지 않고 따로 둔다.

토큰은 저장하지 않는다. ``--token-env``(환경 변수 이름)나 ``--token-file``(파일 경로)로 읽을
곳만 적고, 작업 실행기가 보낼 때 읽는다.
"""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mint_litellm.control import siem
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.types.cli_commands import ADMIN_ONLY, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        path=("siem", "add"),
        summary="SIEM 전달 대상을 추가한다(syslog·CEF·Splunk HEC·Elastic·OTLP). "
        "토큰은 환경 변수 이름이나 파일 경로로만 적는다.",
        roles=ADMIN_ONLY,
        events=(EventKind.SIEM_TARGET_ADDED,),
    ),
    CliCommand(
        path=("siem", "list"), summary="SIEM 전달 대상과 전달 상태를 보인다.", roles=ADMIN_ONLY
    ),
    CliCommand(
        path=("siem", "remove"),
        summary="SIEM 전달 대상을 제거한다.",
        roles=ADMIN_ONLY,
        events=(EventKind.SIEM_TARGET_REMOVED,),
    ),
    CliCommand(
        path=("siem", "test"),
        summary="대상에 시험 메시지를 보낸다(작업 실행기가 보내고 결과를 기다린다).",
        roles=ADMIN_ONLY,
    ),
)

ARGUMENTS: dict[str, list[Any]] = {
    "siem add": [
        (("name",), {"help": "대상 이름(소문자·숫자·-·_)"}),
        (
            ("--kind",),
            {
                "required": True,
                "choices": list(siem.KINDS),
                "help": "syslog, cef(syslog 위 CEF), hec(Splunk), elastic, otlp",
            },
        ),
        (
            ("--endpoint",),
            {
                "required": True,
                "help": "syslog·cef는 tls://호스트:포트·tcp://…·udp://…, 나머지는 http(s)://… 주소",
            },
        ),
        (("--token-env",), {"help": "토큰이 든 환경 변수 이름(작업 실행기의 환경)"}),
        (("--token-file",), {"help": "토큰이 든 파일 경로(작업 실행기가 읽는다)"}),
        (("--index",), {"help": "hec·elastic의 색인 이름"}),
        (("--ca-file",), {"help": "수신 쪽 인증서를 확인할 CA 파일"}),
        (
            ("--framing",),
            {
                "choices": ("octet", "newline"),
                "default": "octet",
                "help": "syslog TCP·TLS 구분 방식(기본 옥텟 세기)",
            },
        ),
        (
            ("--from-start",),
            {"action": "store_true", "help": "지금까지의 사건도 처음부터 보낸다(기본은 지금부터)"},
        ),
    ],
    "siem remove": [(("name",), {"help": "대상 이름"})],
    "siem test": [
        (("name",), {"help": "대상 이름"}),
        (("--no-wait",), {"action": "store_true", "help": "요청만 하고 결과를 기다리지 않는다"}),
    ],
}

WAIT_SECONDS = 60


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")


def _add(run) -> None:
    a = run.args
    if a.token_env and a.token_file:
        raise ControlError("--token-env와 --token-file 중 하나만 쓰십시오.")
    ref = (
        f"env:{a.token_env}"
        if a.token_env
        else f"file:{Path(a.token_file).resolve()}"
        if a.token_file
        else None
    )
    options = {
        k: v
        for k, v in (
            ("index", a.index),
            ("ca_file", a.ca_file),
            ("framing", a.framing if a.framing != "octet" else None),
        )
        if v
    }
    ctx = run.context()
    siem.add(
        run.conn,
        run.cfg.instance_id,
        name=a.name,
        kind=a.kind,
        endpoint=a.endpoint,
        secret_ref=ref,
        options=options,
        from_start=a.from_start,
        created_by=ctx.operator.name,
    )
    ctx.emit(
        EventKind.SIEM_TARGET_ADDED,
        f"{a.name}-{_stamp()}",
        1,
        {"name": a.name, "kind": a.kind, "secret_source": ref.partition(":")[0] if ref else None},
    )
    run.data.update(name=a.name, kind=a.kind)
    run.say(
        f"SIEM 대상 {a.name}을(를) 추가했습니다. 작업 실행기가 15초 안에 전달을 시작합니다. "
        "연결은 `siem test`로 확인하십시오."
    )


def _state(row: dict) -> str:
    if row["failing_since"] is not None:
        return f"실패 중({row['last_error']}, 연속 {row['consecutive_failures']}회)"
    return "정상" if row["last_delivered_at"] else "대기"


def _list(run) -> None:
    rows = siem.listing(run.conn, run.cfg.instance_id)
    run.data["targets"] = [
        {
            k: row[k]
            for k in (
                "name",
                "kind",
                "address",
                "secret_source",
                "cursor_seq",
                "backlog",
                "sent_total",
                "failed_total",
                "last_delivered_at",
                "last_error",
                "failing_since",
            )
        }
        for row in rows
    ]
    if not rows:
        run.say("SIEM 전달 대상이 없습니다. `siem add`로 추가하십시오.")
    for row in rows:
        run.say(
            f"{row['name']}  {row['kind']}  {row['address']}  {_state(row)}  "
            f"밀린 사건 {row['backlog']}건  보낸 {row['sent_total']}건  "
            f"마지막 전달 {row['last_delivered_at'] or '—'}"
        )


def _remove(run) -> None:
    ctx = run.context()
    done = run.conn.execute(
        "DELETE FROM mint.siem_targets WHERE instance_id = %s AND name = %s",
        (run.cfg.instance_id, run.args.name),
    ).rowcount
    if not done:
        raise not_found(f"{run.args.name} 대상이 없습니다.")
    ctx.emit(
        EventKind.SIEM_TARGET_REMOVED, f"{run.args.name}-{_stamp()}", 1, {"name": run.args.name}
    )
    run.say(f"SIEM 대상 {run.args.name}을(를) 제거했습니다.")


def _test(run) -> None:
    name, instance = run.args.name, run.cfg.instance_id
    if not siem.request_test(run.conn, instance, name):
        raise not_found(f"{name} 대상이 없습니다.")
    run.conn.commit()
    if run.args.no_wait:
        run.say("시험 전송을 요청했습니다. `siem list`나 콘솔에서 결과를 확인하십시오.")
        return
    started = fetchone(
        run.conn,
        "SELECT test_requested_at AS at FROM mint.siem_targets"
        " WHERE instance_id = %s AND name = %s",
        (instance, name),
    )["at"]
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        row = fetchone(
            run.conn,
            "SELECT last_test_at, last_test_error FROM mint.siem_targets"
            " WHERE instance_id = %s AND name = %s",
            (instance, name),
        )
        run.conn.commit()
        if row and row["last_test_at"] and row["last_test_at"] >= started:
            if row["last_test_error"]:
                run.failure = f"시험 전송에 실패했습니다: {row['last_test_error']}"
            else:
                run.say("시험 전송에 성공했습니다.")
            return
        time.sleep(1)
    run.failure = "작업 실행기가 응답하지 않습니다. 작업 실행기가 켜져 있는지 확인하십시오."


HANDLERS = {"siem add": _add, "siem list": _list, "siem remove": _remove, "siem test": _test}
