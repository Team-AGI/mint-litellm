"""운영자 명령줄 도구 ``mint-litellm``.

명령 표의 정본은 ``types/cli_commands.py``의 ``COMMANDS``이다. 이 모듈은 표의 모든 명령에
인자와 처리 함수를 붙인다. 인증이 필요한 명령은 토큰으로 운영자를 확인하고, 변경은 한 트랜잭션에서
상태와 사건을 함께 기록한다.
"""

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg

from mint_litellm import cli_evidence, cli_restore
from mint_litellm.control import (
    allowlists,
    approvals,
    checks,
    ledger,
    litellm_config,
    operators,
    org_suggest,
    policy_check,
    policy_versions,
    secrets_file,
    status,
    todo,
    worker,
)
from mint_litellm.control.config import ControlConfig
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import connect, fetchall, fetchone
from mint_litellm.control.db.migrate import apply_migrations
from mint_litellm.control.db.roles import LOGIN_PASSWORD_VARIABLES, LOGIN_ROLES, ensure_login_roles
from mint_litellm.control.errors import AuthError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES
from mint_litellm.control.services import alerts as alert_service
from mint_litellm.control.services import allowlists as allowlist_service
from mint_litellm.control.services import approvals as approval_service
from mint_litellm.control.services import call_approvals as call_approval_service
from mint_litellm.control.services import consents as consent_service
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import policy as policy_service
from mint_litellm.control.services import reads
from mint_litellm.control.services import relations as relation_service
from mint_litellm.control.services import servers as server_service
from mint_litellm.control.services import settings as settings_service
from mint_litellm.control.services import sync as sync_service
from mint_litellm.types import fingerprint
from mint_litellm.types.cli_commands import (
    COMMANDS,
    CONTROL_PLANE_ALLOWED_ROUTES,
    CliCommand,
    OperatorRole,
)
from mint_litellm.types.exec_contract import ExecContract
from mint_litellm.types.identity import SubjectType
from mint_litellm.types.settings import Mode
from mint_litellm.types.target import (
    TargetUnresolved,
    bind_target,
    effective_profile,
    parse_profile_map,
    select_profile,
)

PROGRAM = "mint-litellm"


@dataclass
class Run:
    """명령 한 건의 실행 맥락과 출력. 텍스트와 JSON은 같은 결과에서 만든다."""

    args: argparse.Namespace
    cfg: ControlConfig
    environ: dict[str, str]
    conn: psycopg.Connection
    ctx: Context | None
    emitted: list = field(default_factory=list)
    extra_events: list = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    failure: str | None = None
    failure_code: int = 1

    def context(self) -> Context:
        assert self.ctx is not None
        return self.ctx

    def litellm(self) -> LiteLLMAdmin:
        return self.cfg.litellm()

    def litellm_control(self) -> LiteLLMAdmin:
        return self.cfg.litellm_control()

    def say(self, line: str) -> None:
        self.text.append(line)

    def events(self) -> list:
        return self.ctx.emitted if self.ctx is not None else self.emitted


Handler = Callable[[Run], None]


def _when(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"날짜·시각 형식이 올바르지 않습니다: {text}") from None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _csv(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


# ---------------------------------------------------------------------------
# 처리 함수
# ---------------------------------------------------------------------------


def _init(run: Run) -> None:
    args = run.args
    # 고칠 수 없는 설정이면 아무것도 바꾸기 전에 멈춘다.
    added_modes = (
        litellm_config.ensure_guardrail_modes(Path(args.fix_config)) if args.fix_config else []
    )
    servers_arg: dict[str, tuple[str, str]] = {}
    for item in args.mcp_server or []:
        name, sep, url = item.partition("=")
        if not sep or not name or not url:
            raise ControlError(f"--mcp-server는 이름=URL 형식이어야 합니다: {item}")
        servers_arg[name] = (name, url)
    added_flags = (
        litellm_config.ensure_required_flags(Path(args.fix_config)) if args.fix_config else []
    )
    applied = apply_migrations(run.conn)
    passwords = {
        group: run.environ[var]
        for group, var in LOGIN_PASSWORD_VARIABLES.items()
        if run.environ.get(var)
    }
    configured_roles = ensure_login_roles(run.conn, passwords)
    control_key = settings_service.initialize(
        run.context(), args.org_id, args.org_name, run.cfg.litellm_key
    )
    text = litellm_config.snippet(servers_arg, no_spend_logs=args.no_spend_logs)
    secrets_path = Path(args.secrets_file or run.environ.get("MINT_SECRETS_FILE")
                        or secrets_file.DEFAULT_PATH).expanduser()
    try:
        key_created = secrets_file.ensure_fingerprint_key(secrets_path)
    except OSError as error:
        raise ControlError(f"비밀 파일을 쓸 수 없습니다({secrets_path}): {error}") from None
    run.data.update(
        migrations=applied,
        login_roles=configured_roles,
        fingerprint_key_file=secrets_path.as_posix(),
        fingerprint_key_created=key_created,
    )
    if args.out == "-":
        run.say(text.rstrip("\n"))
        run.data["snippet"] = text
    else:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        run.data["snippet_path"] = path.as_posix()
    log = sys.stderr
    print(f"마이그레이션 적용: {', '.join(applied) or '없음(이미 최신)'}", file=log)
    if args.out != "-":
        print(f"LiteLLM 설정 조각: {args.out}", file=log)
    if added_modes:
        print(
            f"{args.fix_config}의 MINT 가드레일 mode에 {', '.join(added_modes)}을(를) 더했습니다"
            "(바꾸기 전 사본: 같은 폴더의 .bak-* 파일).",
            file=log,
        )
    if added_flags:
        print(
            f"{args.fix_config}에 필수 설정 {', '.join(added_flags)}을(를) 더했습니다"
            "(바꾸기 전 사본: 같은 폴더의 .bak-* 파일).",
            file=log,
        )
    print(
        f"인자 지문 키: {secrets_path}" + (" (새로 생성)" if key_created else " (기존 키 유지)"),
        file=log,
    )
    if configured_roles:
        print(f"로그인 역할 설정: {', '.join(configured_roles)}", file=log)
    elif not passwords:
        print(
            "로그인 역할은 만들지 않았습니다. 플러그인 접속에는 "
            f"{LOGIN_ROLES['mint_plugin']}, 제어 평면에는 {LOGIN_ROLES['mint_control']} "
            "역할을 쓰도록 MINT_PLUGIN_DB_PASSWORD·MINT_CONTROL_DB_PASSWORD를 지정하십시오.",
            file=log,
        )
    if not run.cfg.litellm_key:
        print(
            "제어 평면 LiteLLM 키가 없습니다. deploy/mint.sh up이 자동으로 만들어 넣습니다. "
            "직접 발급하려면 proxy_admin 사용자 키에 allowed_routes를 다음으로 제한하십시오:\n  "
            + ", ".join([*CONTROL_PLANE_ALLOWED_ROUTES, *STAGE2_ALLOWED_ROUTES])
            + "\n그 값을 MINT_LITELLM_KEY로 설정한 뒤 init을 다시 실행하면 이 키가 도구 목록 면제 "
            "키로 저장됩니다(바꿀 때는 settings control-key).",
            file=log,
        )
    notes = {
        "set": "제어 평면 키 저장됨: 서버 승인 때 도구 고정이 이 키로 동작합니다.",
        "differs": "저장된 제어 평면 키와 MINT_LITELLM_KEY가 다릅니다. 바꾸려면 settings "
        "control-key를 실행하십시오.",
    }
    if control_key in notes:
        print(notes[control_key], file=log)


def _control_key(run: Run) -> None:
    if run.args.clear:
        key = None
    elif run.cfg.litellm_key:
        key = run.cfg.litellm_key
    else:
        raise ControlError("MINT_LITELLM_KEY가 설정되어 있지 않습니다(해제는 --clear).")
    run.data["control_key"] = settings_service.set_control_key(run.context(), key)
    run.say("제어 평면 키 " + ("해제됨" if key is None else "저장됨"))


def _gather_env(run: Run) -> dict[str, str]:
    env = dict(run.environ)
    if getattr(run.args, "env_file", None):
        env.update(litellm_config.load_env_file(Path(run.args.env_file)))
    return env


def _env_file_keys(run: Run) -> frozenset[str]:
    path = getattr(run.args, "env_file", None)
    return frozenset(litellm_config.load_env_file(Path(path))) if path else frozenset()


def _config_path(run: Run) -> Path | None:
    return Path(run.args.config) if getattr(run.args, "config", None) else run.cfg.litellm_config


def _optional_litellm(run: Run) -> LiteLLMAdmin | None:
    cfg = run.cfg
    return cfg.litellm() if cfg.litellm_url and cfg.litellm_key else None


def _check(run: Run) -> None:
    ctx = run.context()
    registered = fetchall(
        run.conn,
        "SELECT server_id, status, url_sha256, transport, auth_type, identity_kind"
        " FROM mint.servers WHERE instance_id = %s",
        (ctx.instance_id,),
    )
    report = checks.run_checks(
        litellm_config.load_effective(_config_path(run)),
        _gather_env(run),
        _optional_litellm(run),
        replicas=run.cfg.replicas,
        registered_servers=registered,
        check_fingerprint=True,
        env_file_keys=_env_file_keys(run),
        policy_state=policy_check.verify_active_policy(
            run.conn, ctx.instance_id, run.environ.get("MINT_OPA_URL")
        ),
    )
    checks.target_profile_findings(report, _deployment_basis(run), run.environ)
    run.data.update(
        findings=[
            {"item": f.item, "level": f.level.name, "message": f.message} for f in report.findings
        ],
        observations=report.observations,
    )
    run.say(report.render())
    run.data["incomplete"] = report.incomplete
    if report.failed:
        run.failure = "필수 설정 점검에 실패했습니다."
    elif report.incomplete:
        run.failure = "필수 검증을 모두 수행하지 못했습니다: " + ", ".join(report.incomplete)
        run.failure_code = 3


def _status(run: Run) -> None:
    info = status.collect(
        run.context(),
        run.cfg,
        _optional_litellm(run),
        litellm_config.load_effective(_config_path(run)),
        _gather_env(run),
        policy_check.verify_active_policy(
            run.conn, run.context().instance_id, run.environ.get("MINT_OPA_URL")
        ),
    )
    run.data.update(info)
    run.say(status.render(info))
    state = info["policy_bundle"]["state"] if info.get("policy_bundle") else "none"
    if state == "mismatch":
        run.failure = "활성 정책 판본의 번들 내용이 정책 엔진에 적재된 내용과 다릅니다."
    elif state == "unverified":
        run.failure = "활성 정책 판본의 번들 내용을 확인하지 못했습니다."
        run.failure_code = 3


def _issue_token(run: Run, issue: Callable[[], str]) -> None:
    """토큰을 발급해 알린다. ``--save-token``이면 화면에 보이지 않고 0600 파일로만 받는다.

    파일은 운영자를 등록하기 전에 만들어 두므로 경로가 막혀 있으면 운영자를 만들지 않는다.
    """
    given = getattr(run.args, "save_token", None)
    path = Path(given) if given else None
    if path:
        secrets_file.reserve_private(path)
    try:
        token = issue()
        if path:
            secrets_file.fill_private(path, token)
    except BaseException:
        if path:
            path.unlink(missing_ok=True)
        raise
    if path:
        run.data["token_file"] = given
        run.say(f"토큰을 {given}에 저장했습니다. 이 파일을 --token-file로 주면 인증됩니다.")
        return
    run.data["token"] = token
    run.say(f"발급된 토큰(다시 표시되지 않습니다): {token}")


def _doctor(run: Run) -> None:
    items = todo.collect(run.conn, run.cfg.instance_id)
    if not (run.cfg.litellm_url and run.cfg.litellm_key):
        what = "이 환경에 MINT_LITELLM_URL·MINT_LITELLM_KEY가 없어 LiteLLM 읽기 명령이 실패합니다"
        fix = "deploy/mint.sh cli ... 로 실행하거나 두 환경 변수를 설정하십시오"
        items.insert(0, {"what": what, "next": fix})
    run.data["todo"] = items
    run.say(todo.render(items))


def _operator_add(run: Run) -> None:
    a = run.args
    _issue_token(
        run,
        lambda: operator_service.add(
            run.context(), run.litellm(), a.name, OperatorRole(a.role), a.user_id,
            a.expires_in_days,
        ),
    )


def _operator_bootstrap(run: Run) -> None:
    _issue_token(
        run,
        lambda: operator_service.bootstrap(
            run.conn, run.cfg.instance_id, run.litellm(), run.args.name, run.args.user_id,
            run.emitted,
        ),
    )


def _window_minutes(value: str | None) -> int | None:
    return None if value is None else int(value.removesuffix("m"))


def _second(run: Run) -> Operator | None:
    value = getattr(run.args, "second_approver", None)
    if not value:
        return None
    if value.startswith("@"):
        value = Path(value[1:]).read_text(encoding="utf-8").strip()
    return operators.authenticate(run.conn, run.cfg.instance_id, value)


def _created(run: Run, object_id: str) -> None:
    run.data["id"] = object_id
    run.say(object_id)


def _approve(run: Run) -> None:
    a = run.args
    outside = sorted(set(a.confirm_tool or []) - set(a.tools))
    if outside:
        raise ControlError(f"--confirm-tool은 승인 도구 안에 있어야 합니다: {', '.join(outside)}")
    approval_id, _ = approval_service.approve(
        run.context(),
        run.litellm(),
        relation_id=a.relation,
        scope_type=a.scope,
        scope_id=a.scope_id,
        tools=a.tools,
        valid_from=a.valid_from or datetime.now(UTC),
        valid_until=a.valid_until,
        approval_class=a.approval_class,
        basis_text=a.basis,
        requested_by=a.requested_by,
        allowlist_ids=a.allowlist_ref or [],
        second=_second(run),
        conditions=approvals.build_conditions(
            high_risk_tools=a.high_risk_tools,
            business_hours_only=a.business_hours_only,
            business_hours=a.business_hours,
            require_consent=a.require_consent,
            allowed_hosts=a.allowed_host,
            allowed_paths=a.allowed_path,
            allowed_arg_keys=a.allowed_arg_key,
            confirm_tools=a.confirm_tool,
            confirm_purpose=a.confirm_purpose,
            confirm_fields=a.confirm_field,
            max_result_bytes=a.max_result_bytes,
            max_result_items=a.max_result_items,
            scan_result=not a.no_result_scan,
            response_scan=a.response_scan,
            allow_input_secrets=a.allow_input_secret,
            allow_token_forward=a.allow_token_forward,
        ),
    )
    _created(run, approval_id)


def _subject(a: argparse.Namespace) -> tuple[SubjectType, str]:
    return (SubjectType.TEAM, a.team) if a.team else (SubjectType.USER, a.user)


def _decision_ref(text: str) -> tuple[UUID, int]:
    """오류 본문의 ``reference``(``{invocation_id}:{attempt_id}``)를 나눈다."""
    invocation, sep, attempt = text.rpartition(":")
    try:
        parsed = (UUID(invocation), int(attempt))
    except ValueError:
        parsed = None
    if not sep or parsed is None or parsed[1] < 1:
        raise ControlError("--decision-ref는 <호출 식별자>:<시도 번호> 형식이어야 합니다.")
    return parsed


def _ledger_line(row: dict) -> str:
    """같은 호출의 시도 중 번호가 가장 큰 사건에는 「최종」을, 이전 시도 참조와 사유를 덧붙인다."""
    line = (
        f"{row['inserted_at'].isoformat()}\t{row['kind']}\t{row['actor'] or '-'}\t"
        f"{row['source_key']}"
    )
    payload = row["payload"] if isinstance(row["payload"], dict) else {}
    reasons = [payload.get("stop"), *(payload.get("findings") or [])]
    codes = [r["reason_code"] for r in reasons if isinstance(r, dict) and r.get("reason_code")]
    if codes:
        line += "\t사유 " + ",".join(codes)
    if payload.get("original_decision_ref"):
        line += f"\t이전 시도 {payload['original_decision_ref']}"
    if row["final"] and row["attempt_id"] is not None:
        line += "\t최종"
    return line


def _ledger_list(run: Run) -> None:
    a = run.args
    invocation_id, attempt_id = a.invocation_id, None
    if a.decision_ref:
        if a.invocation_id:
            raise ControlError("--decision-ref와 --invocation-id는 함께 쓸 수 없습니다.")
        invocation_id, attempt_id = _decision_ref(a.decision_ref)
    rows = ledger.list_events(
        run.conn,
        run.cfg.instance_id,
        kind=a.kind,
        since=a.since,
        until=a.until,
        invocation_id=invocation_id,
        attempt_id=attempt_id,
        limit=a.limit,
    )
    run.data["events"] = [json.loads(json.dumps(row, default=str)) for row in rows]
    for row in rows:
        run.say(_ledger_line(row))


def _sync_status(run: Run) -> None:
    rows = sync_service.status(run.context(), held_only=run.args.held)
    run.data["grants"] = [json.loads(json.dumps(row, default=str)) for row in rows]
    for row in rows:
        run.say(
            f"{row['id']}	{row['target_type']}:{row['target_id']}	{row['item']}	"
            f"{row['server_id']}	관측 {row['observed']}	외부 삭제 {row['missing_count']}	"
            f"{'보류' if row['held'] else '-'}"
        )


def _policy_source(run: Run, url_env: str = "MINT_OPA_URL") -> policy_versions.PolicySource:
    a = run.args
    source = policy_versions.PolicySource(
        root=Path(a.policy_root),
        opa=a.opa,
        bundle_path=Path(a.bundle_path),
        opa_url=a.opa_url or run.environ.get(url_env, ""),
        timeout_seconds=a.timeout,
    )
    if not source.opa_url:
        raise ControlError(f"--opa-url 또는 {url_env}이(가) 필요합니다.")
    return source


def _policy_shadow(run: Run) -> None:
    source = _policy_source(run, "MINT_SHADOW_OPA_URL")
    policy_service.shadow_set(run.context(), run.cfg.require_database(), run.args.version, source)
    run.data["id"] = run.args.version


def _policy_shadow_cancel(run: Run) -> None:
    run.data["id"] = policy_service.shadow_cancel(run.context())


def _policy_status(run: Run) -> None:
    ctx = run.context()
    active = fetchone(
        run.conn,
        "SELECT id, activated_at FROM mint.policy_versions"
        " WHERE instance_id = %s AND status = 'active'",
        (ctx.instance_id,),
    )
    shadow = reads.policy_shadow(run.conn, ctx.instance_id)
    run.data["active"] = None if active is None else active["id"]
    run.data["shadow"] = None
    run.say(f"적용 중인 판본: {run.data['active'] or '없음'}")
    if shadow is None:
        run.say("시험 중인 판본: 없음")
        return
    run.data["shadow"] = json.loads(json.dumps(shadow, default=str))
    run.say(status.shadow_line(
        {"version": shadow["version_id"], **shadow["stats"], **shadow["totals"]}
    ))
    for row in shadow["flips"]:
        run.say(
            f"{row['server_id']}	{row['tool']}	{row['active_result']} -> "
            f"{row['shadow_result']}	{row['calls']}건"
        )


def _policy_activate(run: Run) -> None:
    a, ctx = run.args, run.context()
    source = _policy_source(run)
    try:
        row = policy_service.activate(ctx, run.cfg.require_database(), a.version, source)
    except policy_versions.ActivationError as error:
        run.data.update(id=a.version, restore_outcome=error.restore_outcome)
        run.failure = str(error)
        return
    run.data["restore_outcome"] = None
    if row:
        run.extra_events.append(row)
    run.data["id"] = a.version


def _alert_list(run: Run) -> None:
    rows = alert_service.list_alerts(run.context(), status=run.args.status, limit=run.args.limit)
    run.data["alerts"] = [json.loads(json.dumps(row, default=str)) for row in rows]
    for row in rows:
        run.say(
            f"{row['id']}	{row['kind']}	{row['severity']}	{row['status']}	"
            f"{row['count']}	{row['last_at'].isoformat()}"
        )


def _suggest_list(run: Run) -> None:
    rows = org_service.list_suggestions(run.context())
    run.data["suggestions"] = [json.loads(json.dumps(r, default=str)) for r in rows]
    for r in rows:
        run.say(
            f"{r['id']}	{r['subject_type']}	{r['subject_id']}	{r['org_id']}	"
            f"{r['rule']}	{r['matched']}	{r['calls']}"
        )


def _suggest_apply(run: Run) -> None:
    a = run.args
    if bool(a.suggestion_id) == bool(a.rule):
        raise ControlError("제안 식별자와 --rule 중 하나만 주십시오.")
    if a.rule:
        run.data["applied"] = org_service.apply_rule(run.context(), a.rule)
        run.say(f"적용 {run.data['applied']}건")
    else:
        org_service.apply_suggestion(run.context(), a.suggestion_id)


def _domain_list(run: Run) -> None:
    rows = org_service.list_domains(run.context())
    run.data["domains"] = rows
    for r in rows:
        run.say(f"{r['domain']}	{r['org_id']}")


def _server_register(run: Run) -> None:
    server_service.register(
        run.context(),
        run.litellm(),
        run.args.server_id,
        run.args.url,
        litellm_config.load_effective(_config_path(run)),
    )


def _server_register_local(run: Run) -> None:
    try:
        document = json.loads(Path(run.args.contract).read_bytes())
        declared = [{"path": p, "mode": "ro"} for p in run.args.read or ()]
        declared += [{"path": p, "mode": "rw"} for p in run.args.read_write or ()]
        if declared:  # 플래그로 준 선언은 파일의 선언에 더한다(같은 경로는 거부된다)
            document["file_access"] = [*document.get("file_access", ()), *declared]
        contract = ExecContract.model_validate(document)
    except (OSError, ValueError, AttributeError) as exc:
        raise ControlError(f"실행 계약을 읽을 수 없습니다: {exc}") from exc
    server_service.register_local(run.context(), run.args.server_id, contract)


def _done(call: Callable[..., Any], *names: str) -> Handler:
    def handler(run: Run) -> None:
        call(run.context(), *[getattr(run.args, n) for n in names])

    return handler


def _denial(run: Run) -> None:
    a = run.args
    _created(
        run,
        denial_service.deny(
            run.context(),
            scope_type=a.scope,
            scope_id=a.scope_id,
            server_id=a.server,
            tools=a.tools,
            reason=a.reason,
            org_id=a.org,
        ),
    )


def _arguments(a: Any) -> Any:
    text = a.arguments if a.arguments is not None else Path(a.args_file).read_text("utf-8")
    return json.loads(text)


def _deployment_basis(run: Run) -> list[dict]:
    """서버별 승인된 배포 계약의 URL과 승인된 도구 이름. 프로필 자동 선택의 근거이다."""
    return fetchall(
        run.conn,
        "SELECT d.server_id, d.url, coalesce(d.allowed_tools, '{}') ||"
        " coalesce((SELECT array_agg(DISTINCT t.tool) FROM mint.tool_contracts t"
        " WHERE t.instance_id = d.instance_id AND t.server_id = d.server_id"
        " AND t.status = 'approved'), '{}') AS tools"
        " FROM mint.deployment_contracts d WHERE d.instance_id = %s AND d.status = 'approved'",
        (run.context().instance_id,),
    )


def _bound_target(run: Run) -> tuple[str | None, str | None]:
    """프로필이 있는 서버의 승인은 인자 원문에서 플러그인과 같은 규칙으로 대상을 뽑아 묶는다."""
    a = run.args
    try:
        overrides = parse_profile_map(run.environ.get("MINT_TARGET_PROFILES", ""))
    except ValueError as error:
        raise ControlError(f"MINT_TARGET_PROFILES가 올바르지 않습니다: {error}") from None
    auto = None if a.server in overrides else next(
        (select_profile(d["url"], d["tools"] or ())
         for d in _deployment_basis(run) if d["server_id"] == a.server),
        None,
    )
    chosen = effective_profile(overrides, a.server, auto)
    if chosen is None:
        return None, None
    profile = chosen[0]
    if a.args_fp:
        raise ControlError(
            "대상·행위 프로필이 있는 서버는 --arguments 또는 --args-file로 요청해야 합니다."
        )
    try:
        arguments = _arguments(a)
        if not isinstance(arguments, dict):
            raise ValueError("인자는 JSON 객체여야 합니다")
        bound = bind_target(profile, a.server, a.tool, arguments)
    except (ValueError, OSError, TargetUnresolved) as error:
        raise ControlError(f"호출 대상을 정할 수 없습니다: {error}") from None
    return bound.target, bound.action


def _fingerprint(run: Run) -> tuple[str, int]:
    """``--args-fp``는 그대로, 인자 원문은 플러그인과 같은 함수로 지문을 계산한다."""
    a = run.args
    if a.args_fp:
        return a.args_fp, a.fp_key_version or 1
    try:
        arguments = _arguments(a)
        key_text, version = secrets_file.load_fingerprint_key(run.environ)
        key = fingerprint.decode_fingerprint_key(key_text)
        return fingerprint.argument_fingerprint(arguments, key), a.fp_key_version or version
    except (ValueError, OSError) as error:
        raise ControlError(f"인자 지문을 계산할 수 없습니다: {error}") from None


def _call_request(run: Run) -> None:
    a, ctx = run.args, run.context()
    args_fp, fp_key_version = _fingerprint(run)
    target, action = _bound_target(run)
    _created(
        run,
        call_approval_service.request(
            ctx,
            org_id=a.org,
            principal_type=a.principal_type,
            principal_id=a.principal_id,
            server_id=a.server,
            tool=a.tool,
            args_fp=args_fp,
            fp_key_version=fp_key_version,
            policy_version_id=a.policy_version,
            expires_in_minutes=a.expires_in_minutes,
            requested_by=a.requested_by or ctx.operator.user_id or ctx.operator.name,
            target=target,
            action=action,
        ),
    )


def _consent_add(run: Run) -> None:
    a = run.args
    _created(
        run,
        consent_service.add(
            run.context(),
            run.litellm(),
            a.org,
            a.user,
            a.server,
            a.purpose,
            a.data_scope,
            a.text_version,
            a.granted_at or datetime.now(UTC),
            a.valid_until,
            a.evidence_ref,
            a.evidence_sha256,
        ),
    )


def _allowlist_add(run: Run) -> None:
    a = run.args
    _created(
        run,
        allowlist_service.add(
            run.context(),
            a.kind,
            a.value,
            a.valid_from or datetime.now(UTC),
            a.valid_until,
            a.org,
            a.note,
        ),
    )


def _contract(run: Run) -> None:
    a = run.args
    if a.command_name == "contract reapprove":
        result = contract_service.reapprove(
            run.context(), a.server_id, a.intake, a.tool_contract,
            deployment_id=a.deployment_contract, expected_version=a.state_version,
            second=_second(run),
        )
    else:
        fn = contract_service.diff if a.command_name == "contract diff" else contract_service.show
        result = fn(run.context(), a.server_id)
    run.data.update(result)
    run.say(json.dumps(result, ensure_ascii=False, default=str, indent=2))


def _json_arg(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"JSON 형식이 올바르지 않습니다: {text}") from None


def _intake_list(run: Run) -> None:
    rows = intake_service.list_intakes(run.context(), run.args.status)
    run.data["intakes"] = json.loads(json.dumps(rows, default=str))
    for row in rows:
        run.say(f"{row['id']}	{row['status']}	{row['decision'] or '-'}	{row['server_id']}"
                f"	{row['source']}	{row['requested_by'] or '-'}")


def _intake_show(run: Run) -> None:
    info = intake_service.show(run.context(), run.args.intake_id)
    run.data.update(json.loads(json.dumps(info, default=str)))
    row = info["intake"]
    run.say(f"{row['id']}	{row['status']}	{row['decision'] or '-'}	{row['server_id']}")
    for check in info["checks"]:
        run.say(f"  {check['check']}	{check['result']}	{check['reason_code'] or '-'}"
                f"	시도 {check['attempt']}")
    for tool in info["tool_contracts"]:
        run.say(f"  도구 {tool['tool']}	{tool['status']}	{tool['risk_grade'] or '-'}"
                f"	{tool['action_type'] or '-'}")


def _intake_create(run: Run) -> None:
    a = run.args
    _created(
        run,
        intake_service.create(
            run.context(), run.litellm_control(), a.server_id, url=a.url, org_id=a.org,
            purpose=a.purpose, data_grade=a.data_grade, allowed_resources=a.allowed_resources,
            provider=a.provider, owner_user_id=a.owner,
            readiness={"credential_notice": a.credential_notice,
                       "revocation_record": a.revocation_record,
                       "audit_access_days": a.audit_access_days},
            data_return_terms=a.data_return_terms, image_digest=a.image_digest,
            source_commit=a.source_commit,
        ),
    )


def _intake_decide(decision: str) -> Handler:
    def handler(run: Run) -> None:
        a = run.args
        result = intake_service.decide(
            run.context(), a.intake_id, decision, reason=a.reason, valid_until=a.valid_until,
            scope_type=a.scope, scope_id=a.scope_id, team_id=a.team, second=_second(run),
        )
        run.data["id"] = str(result["id"])
        for key in ("approval_id", "relation_id"):
            if key in result:
                run.data[key] = result[key]
        run.say(str(result["id"]))

    return handler


HANDLERS: dict[str, Handler] = {
    "contract show": _contract,
    "contract diff": _contract,
    "contract reapprove": _contract,
    "init": _init,
    "check": _check,
    "status": _status,
    "doctor": _doctor,
    "operator add": _operator_add,
    "operator bootstrap": _operator_bootstrap,
    "operator remove": _done(operator_service.remove, "name"),
    "operator set-role": lambda r: operator_service.set_role(
        r.context(), r.args.name, OperatorRole(r.args.role)
    ),
    "server register": _server_register,
    "server register-local": _server_register_local,
    "alert list": _alert_list,
    "alert ack": _done(alert_service.acknowledge, "alert_id"),
    "alert resolve": _done(alert_service.resolve, "alert_id"),
    "server suspend": _done(server_service.suspend, "server_id"),
    "server resume": _done(server_service.resume, "server_id"),
    "server terminate": _done(server_service.terminate, "server_id"),
    "relation add": lambda r: _created(
        r, relation_service.add(r.context(), r.args.org, r.args.server, r.args.purpose,
                                r.args.team)
    ),
    "relation terminate": _done(relation_service.terminate, "relation"),
    "approve": _approve,
    "deny": _denial,
    "denial lift": _done(denial_service.lift, "denial_id"),
    "revoke": lambda r: approval_service.revoke(
        r.context(), r.args.approval_id, r.args.reason, r.args.deny
    ),
    "call-approval request": _call_request,
    "call-approval approve": lambda r: call_approval_service.approve(
        r.context(), r.args.call_approval_id, _second(r),
        window_minutes=_window_minutes(r.args.for_),
    ),
    "call-approval reject": _done(call_approval_service.reject, "call_approval_id"),
    "call-approval cancel": _done(call_approval_service.cancel, "call_approval_id"),
    "consent add": _consent_add,
    "consent revoke": _done(consent_service.revoke, "consent_id"),
    "allowlist add": _allowlist_add,
    "allowlist lift": _done(allowlist_service.lift, "allowlist_id"),
    "org add": lambda r: org_service.add(r.context(), r.args.org_id, r.args.name),
    "org close": _done(org_service.close, "org_id"),
    "org bind": lambda r: org_service.bind(r.context(), r.args.org, *_subject(r.args)),
    "org unbind": lambda r: org_service.unbind(r.context(), *_subject(r.args)),
    "org suggest": _suggest_list,
    "org suggest apply": _suggest_apply,
    "org suggest ignore": _done(org_service.ignore_suggestion, "suggestion_id"),
    "org domain": _domain_list,
    "org domain set": lambda r: org_service.set_domain(r.context(), r.args.domain, r.args.org),
    "org domain unset": _done(org_service.unset_domain, "domain"),
    "settings default-org": lambda r: settings_service.set_default_org(
        r.context(), None if r.args.clear else r.args.org
    ),
    "settings mode": lambda r: settings_service.set_mode(
        r.context(), Mode(r.args.mode), r.cfg.mode_ceiling
    ),
    "settings control-key": _control_key,
    "settings observable": lambda r: settings_service.set_observable(
        r.context(), r.args.reasons, r.args.policy_ids
    ),
    "policy activate": _policy_activate,
    "policy shadow": _policy_shadow,
    "policy shadow-cancel": _policy_shadow_cancel,
    "policy status": _policy_status,
    "ledger list": _ledger_list,
    "sync status": _sync_status,
    "sync resume": lambda r: sync_service.resume(r.context(), r.args.grant_id),
}


# ---------------------------------------------------------------------------
# 인자 정의
# ---------------------------------------------------------------------------


INTAKE_HANDLERS: dict[str, Handler] = {
    "intake list": _intake_list,
    "intake show": _intake_show,
    "intake create": _intake_create,
    "intake recheck": lambda r: _created(
        r, intake_service.recheck(r.context(), r.args.intake_id,
                                  registry_first=r.args.registry_first, url=r.args.url,
                                  transport=r.args.transport)),
    "intake assign": lambda r: intake_service.assign_requester(
        r.context(), r.litellm(), r.args.intake_id, r.args.requester),
    "intake approve": _intake_decide("approve"),
    "intake reject": _intake_decide("reject"),
    "intake except": _intake_decide("except"),
}

HANDLERS.update(INTAKE_HANDLERS)


def _a(*flags: str, **kwargs: Any) -> tuple[tuple[str, ...], dict[str, Any]]:
    return flags, kwargs


_CONFIG = _a("--config", help="LiteLLM config.yaml 경로(기본: MINT_LITELLM_CONFIG)")
_ENV_FILE = _a("--env-file", help="LiteLLM 환경 파일(KEY=VALUE)")
_SECOND = _a("--second-approver", help="요청자와 다른 사용자의 운영자 토큰(또는 @파일)")
_SERVER_ID = _a("server_id", help="LiteLLM 서버 식별자")
_ALERT_ID = _a("alert_id", help="경보 식별자")
_SAVE_TOKEN = _a("--save-token", help="토큰을 화면에 보이지 않고 이 경로에 0600 파일로 저장")


ARGUMENTS: dict[str, list[Any]] = {
    "contract show": [_SERVER_ID],
    "contract diff": [_SERVER_ID],
    "contract reapprove": [
        _SERVER_ID, _a("--intake", required=True, help="재검사 증거가 있는 신청 식별자"),
        _a("--tool-contract", action="append", default=[], help="후보 도구 계약 식별자(반복 가능)"),
        _a("--deployment-contract", help="후보 배포 계약 식별자"),
        _a("--state-version", type=int, help="서버의 상태 버전"),
        _SECOND,
    ],
    "alert list": [
        _a("--status", choices=["open", "acknowledged", "resolved"], help="상태로 거른다"),
        _a("--limit", type=int, default=100, help="최대 개수(기본 100)"),
    ],
    "alert ack": [_ALERT_ID],
    "alert resolve": [_ALERT_ID],
    "init": [
        _a("--org-id", default="default", help="기본 조직 식별자"),
        _a("--org-name", default="기본 조직", help="기본 조직 이름"),
        _a("--mcp-server", action="append", help="통제할 설정 서버(이름=URL, 반복 가능)"),
        _a("--out", default="config/litellm.mint.yaml",
           help="설정 조각을 쓸 파일(기본: config/litellm.mint.yaml, -는 표준 출력)"),
        _a("--secrets-file",
           help="인자 지문 키를 둘 저장소 밖 비밀 파일"
                "(기본: MINT_SECRETS_FILE 또는 ~/.config/mint/secrets.env)"),
        _a("--no-spend-logs", action="store_true",
           help="disable_spend_logs: true를 설정 조각에 포함"),
        _a("--fix-config",
           help="이 LiteLLM 설정 파일에 MINT 가드레일 mode와 빠진 필수 설정을 더한다(사본 보존)"),
    ],
    "check": [_CONFIG, _ENV_FILE],
    "status": [_CONFIG, _ENV_FILE],
    "doctor": [],
    "operator add": [
        _a("name"),
        _a("--role", required=True, choices=[r.value for r in OperatorRole]),
        _a("--user-id", help="LiteLLM 사용자 식별자(admin·approver 필수)"),
        _a("--expires-in-days", type=int),
        _SAVE_TOKEN,
    ],
    "operator bootstrap": [
        _a("--name", required=True), _a("--user-id", required=True), _SAVE_TOKEN,
    ],
    "operator remove": [_a("name")],
    "operator set-role": [
        _a("name"), _a("--role", required=True, choices=[r.value for r in OperatorRole])
    ],
    "server register": [
        _SERVER_ID,
        _a("--url", help="계약 값에 쓸 서버 URL(제어 평면 키는 레지스트리 URL을 읽을 수 없다)"),
        _CONFIG,
    ],
    "server register-local": [
        _SERVER_ID,
        _a("--contract", required=True, help="실행 계약 JSON 파일 경로"),
        _a("--read", action="append", metavar="PATH", help="서버가 읽을 경로 선언(반복 가능)"),
        _a("--read-write", action="append", metavar="PATH",
           help="서버가 읽고 쓸 경로 선언(반복 가능)"),
    ],
    "server suspend": [_SERVER_ID],
    "server resume": [_SERVER_ID],
    "server terminate": [_SERVER_ID],
    "relation add": [
        _a("--org", required=True),
        _a("--server", required=True),
        _a("--purpose", required=True),
        _a("--team"),
    ],
    "relation terminate": [_a("relation", help="이용 관계 식별자")],
    "approve": [
        _a("--relation", required=True),
        _a("--scope", required=True, choices=approvals.SCOPE_TYPES),
        _a("--scope-id", required=True),
        _a("--tools", required=True, type=_csv, help="쉼표로 구분한 도구 이름"),
        _a("--valid-from", type=_when),
        _a("--valid-until", required=True, type=_when),
        _a("--class", dest="approval_class", default="standard",
           choices=["standard", "exception"]),
        _a("--basis", required=True, help="승인 근거"),
        _a("--requested-by", required=True, help="신청자의 LiteLLM 사용자 식별자"),
        _a("--allowlist-ref", action="append", help="근거 허용 목록 항목 식별자(첫 승인에서만)"),
        _a("--high-risk-tools", type=_csv, help="이 승인에서 호출별 승인을 요구할 도구(쉼표 구분)"),
        _a("--business-hours-only", action="store_true", help="업무 시간 밖의 호출을 차단"),
        _a("--business-hours",
           help="업무 시간 재정의: 시간대,요일,시작,끝 (예: Asia/Seoul,1-5,09:00,18:00)"),
        _a("--require-consent", help="이 목적의 동의가 있어야 호출 허용"),
        _a("--allowed-host", action="append", help="허용 목적지 호스트(반복 가능)"),
        _a("--allowed-path", action="append", help="허용 폴더의 절대 경로(반복 가능)"),
        _a("--allowed-arg-key", action="append", help="허용 인자 이름(반복 가능)"),
        _a("--max-result-bytes", type=int,
           help="결과 한 건의 크기 상한(바이트). 넘으면 결과를 막는다"),
        _a("--max-result-items", type=int, help="결과 한 건의 항목(내용 블록) 수 상한"),
        _a("--no-result-scan", action="store_true",
           help="결과 본문의 지시문 표지 검사를 끈다(계약 관리 서버는 기본으로 검사한다)"),
        _a("--response-scan", choices=["block", "mask", "observe"],
           help="결과의 비밀·개인정보 처리: block(결과를 막음), mask(찾은 값만 가림, 기본), "
           "observe(기록만)"),
        _a("--allow-input-secret", action="append",
           help="인자에서 비밀을 찾아도 이 승인의 도구에 한해 허용할 탐지 종류(반복 가능). "
           "기본은 인자에 비밀이 있으면 막는다"),
        _a("--allow-token-forward", action="store_true",
           help="호출자 토큰을 업스트림에 그대로 전달하는 서버(true_passthrough·oauth_delegate)의 "
           "호출을 이 승인에서 허용한다. 기본은 막는다"),
        _a("--confirm-tool", action="append",
           help="호출 때 본인 확인을 요구할 도구(반복 가능, 승인 도구 안에 있어야 한다)"),
        _a("--confirm-purpose", help="본인 확인의 목적(--confirm-tool과 함께)"),
        _a("--confirm-field", action="append", help="확인 화면에 보일 인자 이름(반복 가능)"),
        _SECOND,
    ],
    "deny": [
        _a("--scope", required=True, choices=[*approvals.SCOPE_TYPES, "server"]),
        _a("--scope-id", required=True),
        _a("--server"),
        _a("--tools", type=_csv),
        _a("--reason", required=True),
        _a("--org"),
    ],
    "denial lift": [_a("denial_id")],
    "revoke": [
        _a("approval_id"),
        _a("--reason", required=True),
        _a("--deny", action="store_true", help="같은 범위의 거부를 함께 만든다"),
    ],
    "call-approval request": [
        _a("--org", required=True),
        _a("--principal-type", required=True, choices=list(approvals.PRINCIPAL_TYPES)),
        _a("--principal-id", required=True),
        _a("--server", required=True),
        _a("--tool", required=True),
        "FINGERPRINT",
        _a("--fp-key-version", type=int,
           help="지문 키 판본(기본: MINT_FINGERPRINT_KEY_VERSION 또는 1)"),
        _a("--policy-version", help="기본: 활성 정책 판본"),
        _a("--expires-in-minutes", type=int, default=30),
        _a("--requested-by", help="기본: 운영자의 사용자 식별자"),
    ],
    "call-approval approve": [
        _a("call_approval_id"), _SECOND,
        _a("--for", dest="for_", choices=["10m", "30m"],
           help="같은 호출을 이 시간 동안 되풀이해 승인한다(기본: 1회)"),
    ],
    "call-approval reject": [_a("call_approval_id")],
    "call-approval cancel": [_a("call_approval_id")],
    "consent add": [
        _a("--org", required=True),
        _a("--user", required=True, help="동의한 사람의 LiteLLM 사용자 식별자"),
        _a("--server", required=True),
        _a("--purpose", required=True),
        _a("--data-scope", required=True),
        _a("--text-version", required=True),
        _a("--granted-at", type=_when),
        _a("--valid-until", required=True, type=_when),
        _a("--evidence-ref", required=True),
        _a("--evidence-sha256", required=True),
    ],
    "consent revoke": [_a("consent_id")],
    "allowlist add": [
        _a("--kind", required=True, choices=list(allowlists.KINDS)),
        _a("--value", required=True),
        _a("--valid-from", type=_when),
        _a("--valid-until", required=True, type=_when),
        _a("--org"),
        _a("--note"),
    ],
    "allowlist lift": [_a("allowlist_id")],
    "org add": [_a("org_id"), _a("--name", required=True)],
    "org close": [_a("org_id")],
    "org bind": [_a("--org", required=True), "SUBJECT"],
    "org unbind": ["SUBJECT"],
    "org suggest apply": [
        _a("suggestion_id", nargs="?"),
        _a("--rule", choices=list(org_suggest.RULES), help="이 규칙의 열린 제안 전체"),
    ],
    "org suggest ignore": [_a("suggestion_id")],
    "org domain set": [_a("domain"), _a("--org", required=True)],
    "org domain unset": [_a("domain")],
    "settings default-org": ["ORG_OR_CLEAR"],
    "settings mode": [_a("mode", choices=[m.value for m in Mode])],
    "settings control-key": [_a("--clear", action="store_true", help="저장된 키를 해제한다")],
    "settings observable": [
        _a("--reasons", type=_csv, help="관측으로 전환할 수 있는 사유 계열(쉼표 구분)"),
        _a("--policy-ids", type=_csv, help="관측에 쓸 정책 식별자(쉼표 구분)"),
    ],
    "policy activate": [
        _a("version", help="정책 판본 식별자"),
        _a("--policy-root", default=os.environ.get("MINT_POLICY_ROOT", "/opt/mint"),
           help="policy/ 디렉터리를 담은 루트(기본: MINT_POLICY_ROOT 또는 /opt/mint)"),
        _a("--opa", default="opa", help="정책 시험에 쓸 opa 실행 파일"),
        _a("--bundle-path",
           default=os.environ.get("MINT_OPA_BUNDLE_PATH", "/bundles/mint.tar.gz"),
           help="정책 엔진이 감시하는 번들 파일(공유 볼륨)"),
        _a("--opa-url", help="정책 엔진 주소(기본: MINT_OPA_URL)"),
        _a("--timeout", type=float, default=30.0, help="엔진 적재 확인 제한 시간(초)"),
    ],
    "policy shadow": [
        _a("version", help="시험할 정책 판본 식별자(적용 중인 판본과 달라야 한다)"),
        _a("--policy-root", default=os.environ.get("MINT_POLICY_ROOT", "/opt/mint"),
           help="policy/ 디렉터리를 담은 루트(기본: MINT_POLICY_ROOT 또는 /opt/mint)"),
        _a("--opa", default="opa", help="정책 시험에 쓸 opa 실행 파일"),
        _a("--bundle-path",
           default=os.environ.get("MINT_OPA_SHADOW_BUNDLE_PATH", "/bundles/shadow.tar.gz"),
           help="시험용 정책 엔진이 감시하는 번들 파일(공유 볼륨)"),
        _a("--opa-url", help="시험용 정책 엔진 주소(기본: MINT_SHADOW_OPA_URL)"),
        _a("--timeout", type=float, default=30.0, help="엔진 적재 확인 제한 시간(초)"),
    ],
    "sync status": [_a("--held", action="store_true", help="보류된 항목만 보인다")],
    "sync resume": [_a("grant_id", help="동기화 항목 식별자(`sync status`의 첫 열)")],
    "ledger list": [
        _a("--kind"),
        _a("--since", type=_when),
        _a("--until", type=_when),
        _a("--invocation-id", type=UUID),
        _a("--decision-ref",
           help="오류 본문의 reference(<호출 식별자>:<시도 번호>)로 판정 사건을 찾는다"),
        _a("--limit", type=int, default=100),
    ],
}


_INTAKE_ID = _a("intake_id", help="신청 식별자")
_DECISION = [
    _INTAKE_ID,
    _a("--reason", help="결정 사유(거절·예외는 필수)"),
    _a("--valid-until", type=_when, help="승인 유효 기간의 끝(기본 90일, 고위험 도구·예외는 30일)"),
    _a("--scope", choices=["key", "user", "team"], help="승인 범위(기본: 책임자 사용자)"),
    _a("--scope-id", help="승인 범위의 식별자(기본: 책임자)"),
    _a("--team", help="이용 관계의 팀"),
    _SECOND,
]

INTAKE_ARGUMENTS: dict[str, list[Any]] = {
    "intake list": [_a("--status", choices=["received", "checking", "passed", "failed",
                                            "indeterminate", "decided"])],
    "intake show": [_INTAKE_ID],
    "intake create": [
        _SERVER_ID,
        _a("--url", help="계약 값에 쓸 서버 URL(제어 평면 키는 레지스트리 URL을 읽을 수 없다)"),
        _a("--org", help="조직(기본: 운영자 사용자에서 유도)"),
        _a("--purpose", required=True),
        _a("--data-grade", required=True, choices=list(intake_service.DATA_GRADES)),
        _a("--allowed-resources", type=_json_arg,
           help="허용 자원(JSON 배열 또는 객체). 제출에서 채워진 값이 있으면 생략"),
        _a("--provider", help="제공자. 제출에서 채워진 값이 있으면 생략"),
        _a("--owner", help="책임자의 LiteLLM 사용자 식별자. 제출에서 채워진 값이 있으면 생략"),
        _a("--credential-notice", required=True, help="자격 통지 확보 방법"),
        _a("--revocation-record", required=True, help="철회 기록 확보 방법"),
        _a("--audit-access-days", required=True, type=int, help="감사 접근 보장 일수"),
        _a("--data-return-terms", required=True, help="자료 삭제·반환 조건"),
        _a("--image-digest", help="자체 배포 서버의 이미지 다이제스트"),
        _a("--source-commit", help="자체 배포 서버의 소스 커밋"),
    ],
    "intake recheck": [
        _INTAKE_ID,
        _a("--registry-first", action="store_true",
           help="제출 서버를 LiteLLM 레지스트리에 올린 뒤 검사(키 권한은 주지 않는다)"),
        _a("--url", help="승인된 신청의 새 배포 주소(관측된 URL 해시와 같아야 한다)"),
        _a("--transport", help="새 배포 주소의 전송 방식(기본은 승인된 값)"),
    ],
    "intake assign": [_INTAKE_ID, _a("--requester", required=True, help="신청자 사용자 식별자")],
    "intake approve": _DECISION,
    "intake reject": _DECISION,
    "intake except": _DECISION,
}

ARGUMENTS.update(INTAKE_ARGUMENTS)


def _add_arguments(parser: argparse.ArgumentParser, name: str) -> None:
    for spec in {**ARGUMENTS, **cli_restore.ARGUMENTS, **cli_evidence.ARGUMENTS}.get(name, []):
        if spec == "SUBJECT":
            group = parser.add_mutually_exclusive_group(required=True)
            group.add_argument("--team")
            group.add_argument("--user")
        elif spec == "FINGERPRINT":
            group = parser.add_mutually_exclusive_group(required=True)
            group.add_argument("--args-fp", help="차단 사건에 기록된 인자 지문(소문자 16진 64자)")
            group.add_argument("--arguments", help="호출 인자(JSON 객체), 지문 키로 지문을 계산")
            group.add_argument("--args-file", help="호출 인자를 담은 JSON 파일")
        elif spec == "ORG_OR_CLEAR":
            group = parser.add_mutually_exclusive_group(required=True)
            group.add_argument("--org")
            group.add_argument("--clear", action="store_true", help="기본 조직 해제")
        else:
            flags, kwargs = spec
            parser.add_argument(*flags, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog=PROGRAM, description="MINT 운영자 명령줄 도구")
    root.add_argument("--token-file", help="운영자 토큰 파일(기본: MINT_OPERATOR_TOKEN)")
    root.add_argument("--json", action="store_true", help="결과를 JSON 한 개로 출력")
    tree: dict[tuple[str, ...], argparse._SubParsersAction] = {(): root.add_subparsers(
        dest="group0", metavar="명령", required=True)}
    commands = [*COMMANDS, *cli_restore.COMMANDS, *cli_evidence.COMMANDS]
    # 하위 명령도 가진 명령(``org suggest``)은 하위 명령 없이 부르면 자기 자신이 실행된다.
    parents = {c.path for c in commands if any(o.path[:len(c.path)] == c.path != o.path
                                              for o in commands)}
    for command in commands:
        for depth in range(1, len(command.path)):
            prefix = command.path[:depth]
            if prefix not in tree:
                parent = tree[prefix[:-1]]
                group = parent.add_parser(prefix[-1], help=prefix[-1])
                tree[prefix] = group.add_subparsers(
                    dest=f"group{depth}", metavar="명령", required=True)
        leaf = tree[command.path[:-1]].add_parser(command.path[-1], help=command.summary)
        leaf.set_defaults(command_name=command.name)
        leaf.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                          help="결과를 JSON 한 개로 출력")
        _add_arguments(leaf, command.name)
        if command.path in parents:
            tree[command.path] = leaf.add_subparsers(
                dest=f"group{len(command.path)}", metavar="명령", required=False)
    # 작업 실행기는 운영자 명령이 아니라 상주 프로세스라 명령 표(COMMANDS)에 없다.
    tree[()].add_parser("worker", help="작업 실행기를 기동한다").set_defaults(
        process="worker")
    serve = tree[()].add_parser("console", help="관리자 콘솔을 기동한다")
    serve.set_defaults(process="console")
    serve.add_argument(
        "--host", default="localhost", help="수신 주소(기본 localhost, *는 모든 주소)")
    serve.add_argument("--port", type=int, default=8080, help="수신 포트(기본 8080)")
    serve.add_argument("--ssl-certfile", help="TLS 인증서 파일(앞단에서 TLS를 끝내면 생략)")
    serve.add_argument("--ssl-keyfile", help="TLS 개인 키 파일")
    return root


COMMAND_INDEX: dict[str, CliCommand] = {
    c.name: c for c in [*COMMANDS, *cli_restore.COMMANDS, *cli_evidence.COMMANDS]
}


def _token(args: argparse.Namespace, environ: dict[str, str]) -> str | None:
    if args.token_file:
        try:
            return Path(args.token_file).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise AuthError(f"토큰 파일을 읽을 수 없습니다: {error}") from None
    return environ.get("MINT_OPERATOR_TOKEN")


def _event_entry(event: Any) -> dict[str, Any]:
    """사건(객체 또는 행)을 JSON 출력용으로 줄인다. 식별자와 상태 버전은 source_key에서 읽는다."""
    get = event.get if isinstance(event, dict) else lambda key: getattr(event, key)
    key = str(get("source_key"))
    entity, entity_id, version, _ = key.split(":", 3)
    return {
        "event_id": str(get("event_id")),
        "kind": str(getattr(get("kind"), "value", get("kind"))),
        "source_key": key,
        "entity": entity,
        "entity_id": entity_id,
        "state_version": int(version),
    }


def _result(run: Run, command: CliCommand) -> dict[str, Any]:
    entries = [_event_entry(e) for e in [*run.events(), *run.extra_events]]
    result: dict[str, Any] = {"ok": run.failure is None, "command": command.name}
    result.update(run.data)
    if entries:
        result.setdefault("id", entries[0]["entity_id"])
        result["state_version"] = entries[0]["state_version"]
        result["events"] = entries
    return result


# 목록에 나온 식별자를 끝 8자리(또는 앞부분)만으로 가리킬 수 있는 인자. 인자 이름 -> 표
ID_ARGUMENTS = {
    "alert_id": "alerts",
    "intake_id": "intakes",
    "call_approval_id": "call_approvals",
    "grant_id": "litellm_grants",
    "approval_id": "approvals",
    "denial_id": "denials",
    "consent_id": "consents",
    "allowlist_id": "allowlists",
}
_SHORT_ID = re.compile(r"[0-9a-fA-F-]{6,35}")


def expand_ids(run: Run) -> None:
    """식별자 인자가 전체 형식이 아니면 이 배치에서 앞이나 끝이 일치하는 한 건으로 바꾼다.

    일치하는 것이 없으면 그대로 두어 서비스가 없다고 알리고, 둘 이상이면 더 길게 입력하라고 한다.
    """
    for name, table in ID_ARGUMENTS.items():
        value = getattr(run.args, name, None)
        if not isinstance(value, str) or not _SHORT_ID.fullmatch(value):
            continue
        found = fetchall(
            run.conn,
            f"SELECT id::text AS id FROM mint.{table} WHERE instance_id = %s"
            " AND (id::text LIKE %s OR id::text LIKE %s) LIMIT 2",
            (run.cfg.instance_id, value.lower() + "%", "%" + value.lower()),
        )
        if len(found) > 1:
            raise ControlError(f"{value}과(와) 일치하는 식별자가 둘 이상입니다. 더 길게 쓰십시오.")
        if found:
            setattr(run.args, name, found[0]["id"])


def _missing_token_message(conn: psycopg.Connection, instance_id: str) -> str:
    """토큰이 없을 때 다음에 할 일까지 알린다. 운영자가 없으면 첫 관리자를 만드는 명령을 낸다."""
    try:
        has_operator = fetchall(
            conn, "SELECT 1 AS x FROM mint.operators WHERE instance_id = %s LIMIT 1", (instance_id,)
        )
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return "데이터베이스가 준비되지 않았습니다. 먼저 mint-litellm init을 실행하십시오."
    if not has_operator:
        return (
            "운영자가 아직 없습니다. 첫 관리자를 만드십시오: mint-litellm operator bootstrap "
            "--name <이름> --user-id <LiteLLM 사용자> --save-token <파일>"
        )
    return (
        "운영자 토큰이 필요합니다(MINT_OPERATOR_TOKEN 또는 --token-file). "
        "토큰은 관리자가 operator add로 발급합니다."
    )


def run_command(args: argparse.Namespace, environ: dict[str, str]) -> None:
    command = COMMAND_INDEX[args.command_name]
    cfg = ControlConfig.from_env(environ)
    with connect(cfg.require_database()) as conn:
        ctx = None
        if command.name == "init":
            ctx = Context(conn, cfg.instance_id, Operator("init", "admin", None))
        elif not command.unauthenticated:
            token = _token(args, environ)
            if not token:
                raise AuthError(_missing_token_message(conn, cfg.instance_id))
            operator = operators.authenticate(conn, cfg.instance_id, token)
            if OperatorRole(operator.role) not in command.roles:
                raise AuthError(f"{command.name}은(는) {operator.role} 역할로 실행할 수 없습니다.")
            ctx = Context(conn, cfg.instance_id, operator)
        run = Run(args, cfg, environ, conn, ctx)
        if ctx is not None:
            expand_ids(run)
        extra = {**cli_restore.HANDLERS, **cli_evidence.HANDLERS}
        (HANDLERS.get(command.name) or extra[command.name])(run)
    if args.json:
        print(json.dumps(_result(run, command), ensure_ascii=False, default=str))
    else:
        for line in run.text:
            print(line)
    if run.failure:
        raise ControlError(run.failure, run.failure_code)


def main(argv: Sequence[str] | None = None, environ: dict[str, str] | None = None) -> int:
    environ = dict(os.environ) if environ is None else environ
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "process", None) == "worker":
            return worker.main(environ)
        if getattr(args, "process", None) == "console":
            from mint_litellm.console.server import serve

            return serve(args, environ)
        run_command(args, environ)
    except ControlError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code
    except psycopg.Error as error:
        print(f"데이터베이스 오류: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
