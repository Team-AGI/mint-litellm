"""업그레이드 보조 명령(``./mint.sh upgrade``가 부른다). 1단계 명령 표는 건드리지 않는다."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mint_litellm.control import upgrade_report
from mint_litellm.control.db.connection import fetchone
from mint_litellm.endpoint import kit_build
from mint_litellm.plugin.policy import bundle as policy_bundle
from mint_litellm.types.cli_commands import ADMIN_ONLY, ALL_ROLES, CliCommand
from mint_litellm.types.events import EventKind

COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        path=("upgrade", "policy"),
        summary="저장소의 정책 카탈로그가 적용 중인 판본과 다르면 새 판본으로 활성화한다. "
        "`--check`는 바뀌었는지만 알린다.",
        roles=ADMIN_ONLY,
        events=(EventKind.POLICY_ACTIVATED,),
    ),
    CliCommand(
        path=("upgrade", "report"),
        summary="업그레이드 뒤 사람이 정해야 하는 일을 데이터베이스에서 계산해 보인다(읽기 전용).",
        roles=ALL_ROLES,
    ),
)

ARGUMENTS: dict[str, list[Any]] = {
    "upgrade policy": [
        (("--check",), {"action": "store_true", "help": "활성화하지 않고 바뀌었는지만 알린다"}),
        (("--policy-root",), {
            "default": os.environ.get("MINT_POLICY_ROOT", "/opt/mint"),
            "help": "policy/ 디렉터리를 담은 루트(기본: MINT_POLICY_ROOT 또는 /opt/mint)"}),
        (("--opa",), {"default": "opa", "help": "정책 시험에 쓸 opa 실행 파일"}),
        (("--bundle-path",), {
            "default": os.environ.get("MINT_OPA_BUNDLE_PATH", "/bundles/mint.tar.gz"),
            "help": "정책 엔진이 감시하는 번들 파일(공유 볼륨)"}),
        (("--opa-url",), {"help": "정책 엔진 주소(기본: MINT_OPA_URL)"}),
        (("--timeout",), {"type": float, "default": 30.0,
                          "help": "엔진 적재 확인 제한 시간(초)"}),
    ],
    "upgrade report": [],
}


def _policy(run) -> None:
    from mint_litellm import cli  # cli가 이 모듈을 불러오므로 늦게 가져온다

    a = run.args
    prepared = policy_bundle.prepare_bundle(Path(a.policy_root), "probe", opa=a.opa)
    active = fetchone(
        run.conn,
        "SELECT id, catalog_sha256 FROM mint.policy_versions"
        " WHERE instance_id = %s AND status = 'active'",
        (run.cfg.instance_id,),
    )
    version = f"catalog-{prepared.catalog_sha256[:12]}"
    changed = active is None or active["catalog_sha256"] != prepared.catalog_sha256
    run.data.update(changed=changed, version=version)
    if not changed:
        run.say(f"정책 카탈로그가 적용 중인 판본 {active['id']}과(와) 같습니다.")
        return
    if a.check:
        run.say(f"정책 카탈로그가 바뀌었습니다. 새 판본 {version}을(를) 활성화해야 합니다.")
        return
    a.version = version
    cli._policy_activate(run)
    if not run.failure:
        run.say(f"정책 판본 {version}을(를) 활성화했습니다.")


def _report(run) -> None:
    # 전체 설정(내보내기 폴더 등)을 요구하지 않도록 재확인 주기만 환경에서 읽는다.
    days = run.environ.get("MINT_RECERT_DAYS", "")
    items = upgrade_report.collect(
        run.conn, run.cfg.instance_id, now=datetime.now(UTC),
        recert_period=timedelta(days=int(days) if days.isdigit() and int(days) > 0 else 90),
        current_kit=kit_build.kit_version(),
    )
    run.data["decisions"] = items
    run.say(upgrade_report.render(items))


HANDLERS = {"upgrade policy": _policy, "upgrade report": _report}
