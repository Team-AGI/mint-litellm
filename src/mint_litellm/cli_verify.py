"""방어 검증 명령(``verify run``). 시험 전용 키로 승인된 읽기 도구에 합성 위험 입력을 보내고
원장 판정과 기대를 대조한다. 1단계 명령 표는 건드리지 않는다."""

from pathlib import Path
from typing import Any

from mint_litellm.control import defense_verify
from mint_litellm.control.errors import ControlError
from mint_litellm.control.key_block import VERIFY_ALIAS_PREFIX
from mint_litellm.types.cli_commands import ADMIN_ONLY, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        path=("verify", "run"),
        summary="대상 서버의 승인된 읽기 도구에 합성 위험 입력(경로·주소·비밀·식별번호와 대조군)을 "
        "게이트웨이로 보내고, 원장의 판정이 기대와 같은지 대조한다. 시험 전용 키는 운영자가 "
        "미리 만들어 `--key-file`로 준다. 실패가 있으면 종료 코드 1이고 경보를 연다.",
        roles=ADMIN_ONLY,
        litellm_reads=("/key/info",),
        events=(EventKind.DEFENSE_VERIFY_RUN,),
    ),
)

ARGUMENTS: dict[str, list[Any]] = {
    "verify run": [
        (("--server",), {"required": True, "help": "대상 서버 식별자"}),
        (("--profile",), {"default": "default", "choices": ["default"], "help": "시험집"}),
        (("--gateway",), {"help": "LiteLLM 주소(기본: MINT_LITELLM_URL)"}),
        (("--key-file",), {"required": True,
                           "help": f"시험 전용 키 파일(키 이름이 `{VERIFY_ALIAS_PREFIX}`로 시작)"}),
        (("--allowed-host",), {"help": "승인된 목적지 호스트(허용 대조 항목을 실행한다)"}),
        (("--test-server",), {"action": "store_true",
                              "help": "대상이 MINT가 통제하는 시험 서버이다(결과 쪽 항목 실행)"}),
        (("--max-calls",), {"type": int, "default": defense_verify.MAX_CALLS,
                            "help": "서버당 호출 상한"}),
    ],
}

_MARK = {"pass": "통과", "fail": "실패", "warn": "경고", "skipped": "건너뜀"}


def _run(run) -> None:
    a = run.args
    gateway = a.gateway or run.cfg.litellm_url
    if not gateway:
        raise ControlError("LiteLLM 주소가 필요합니다(--gateway 또는 MINT_LITELLM_URL).")
    key = Path(a.key_file).read_text(encoding="utf-8").strip()
    info = run.litellm().get_key(defense_verify.key_id_of(key))
    alias = str((info or {}).get("key_alias") or "")
    if not alias.startswith(VERIFY_ALIAS_PREFIX):
        raise ControlError(
            f"시험 키가 아닙니다. 키 이름이 `{VERIFY_ALIAS_PREFIX}`로 시작하는 전용 키를 쓰십시오."
        )
    result = defense_verify.run_verify(
        run.context(), server_id=a.server, key=key, gateway=gateway,
        allowed_host=a.allowed_host or "", test_server=a.test_server,
        max_calls=min(a.max_calls, defense_verify.MAX_CALLS),
    )
    run.data.update(result)
    for r in result["results"]:
        run.say(f"{r['id']}\t{_MARK[r['status']]}\t{r['group']}\t{r.get('expect', '-')}\t"
                f"{r['note']}")
    c = result["counts"]
    run.say(f"통과 {c['pass']}  경고 {c['warn']}  실패 {c['fail']}  건너뜀 {c['skipped']}"
            f"  (시험집 {result['profile_version']})")
    if c["fail"]:
        run.failure = f"방어 검증에서 {c['fail']}건이 기대와 달랐습니다."


HANDLERS = {"verify run": _run}
