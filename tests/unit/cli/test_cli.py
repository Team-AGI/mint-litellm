"""명령줄 도구: 명령 표와의 일치, 인증·역할, 성공 경로, 종료 코드."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from litellm_stub import CONTROL_KEY, GOOD_KEY

psycopg = pytest.importorskip("psycopg")

from mint_litellm import cli  # noqa: E402
from mint_litellm.types.cli_commands import COMMANDS, OperatorRole  # noqa: E402

FAR_FUTURE = (datetime.now(UTC) + timedelta(days=400)).isoformat()


def test_every_command_in_the_table_has_a_handler_and_a_parser():
    names = {c.name for c in COMMANDS}
    assert names == set(cli.HANDLERS)
    assert set(cli.ARGUMENTS) <= names
    parser = cli.build_parser()
    for command in COMMANDS:
        with pytest.raises(SystemExit) as raised:
            parser.parse_args([*command.path, "--help"])
        assert raised.value.code == 0


def test_help_summaries_come_from_the_command_table(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    for top in {c.path[0] for c in COMMANDS}:
        assert top in out


class Cli:
    def __init__(self, db_url, litellm_url, capsys, tmp_path):
        self.env = {
            "MINT_DATABASE_URL": db_url,
            "MINT_INSTANCE_ID": "clitest",
            "MINT_LITELLM_URL": litellm_url,
            "MINT_LITELLM_KEY": CONTROL_KEY,
            # 시험이 사용자의 실제 비밀 파일을 만들지 않도록 시험별 경로로 격리한다.
            "MINT_SECRETS_FILE": str(tmp_path / "isolated-secrets.env"),
        }
        self.capsys = capsys
        self.tmp = tmp_path

    def run(self, *argv, token=None):
        env = dict(self.env)
        if token:
            env["MINT_OPERATOR_TOKEN"] = token
        code = cli.main(list(argv), env)
        captured = self.capsys.readouterr()
        return code, captured.out, captured.err

    @staticmethod
    def token(out: str) -> str:
        return out.rsplit(": ", 1)[1].strip()


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def bootstrap(mint) -> str:
    code, out, _ = mint.run("init")
    assert code == 0
    code, out, err = mint.run("operator", "bootstrap", "--name", "boss", "--user-id", "human-2")
    assert code == 0, err
    return mint.token(out)


def test_init_creates_the_default_org_settings_and_prints_the_snippet(mint):
    path = mint.tmp / "snippet.yaml"
    code, out, err = mint.run("init", "--mcp-server", "docs=http://u.test/mcp",
                              "--out", str(path))
    assert code == 0 and "마이그레이션 적용" in err and "제어 평면 키 저장됨" in err
    assert "server_id: docs" in path.read_text(encoding="utf-8")
    again, _, err = mint.run("init")
    assert again == 0 and "이미 최신" in err
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        settings = conn.execute(
            "SELECT default_org_id, observable_policy_ids FROM mint.settings"
        ).fetchone()
        assert settings == ("default", ["R1", "R3"])
        kinds = [r[0] for r in conn.execute("SELECT kind FROM mint.events ORDER BY inserted_at")]
        assert kinds == ["settings_changed", "org_created", "settings_changed", "settings_changed"]
        token = conn.execute("SELECT control_key_token FROM mint.settings").fetchone()[0]
        assert token == hashlib.sha256(CONTROL_KEY.encode()).hexdigest()


def test_init_keeps_a_stored_control_key_and_the_command_replaces_or_clears_it(mint):
    token = bootstrap(mint)
    stored = lambda: psycopg.connect(mint.env["MINT_DATABASE_URL"]).execute(  # noqa: E731
        "SELECT control_key_token FROM mint.settings").fetchone()[0]
    first = stored()
    mint.env["MINT_LITELLM_KEY"] = "sk-other-control-key"
    code, _, err = mint.run("init")
    assert code == 0 and "settings control-key" in err and stored() == first
    assert mint.run("settings", "control-key", token=token)[0] == 0
    assert stored() == hashlib.sha256(b"sk-other-control-key").hexdigest()
    assert mint.run("settings", "control-key", "--clear", token=token)[0] == 0
    assert stored() is None
    del mint.env["MINT_LITELLM_KEY"]
    code, _, err = mint.run("settings", "control-key", token=token)
    assert code == 1 and "MINT_LITELLM_KEY" in err


def test_init_no_spend_logs_and_bad_server_argument(mint):
    code, out, _ = mint.run("init", "--no-spend-logs", "--out", "-")
    assert code == 0 and "disable_spend_logs: true" in out
    code, _, err = mint.run("init", "--mcp-server", "missing-url")
    assert code == 1 and "이름=URL" in err


def test_init_creates_login_roles_when_passwords_are_given(mint):
    mint.env["MINT_PLUGIN_DB_PASSWORD"] = "plugin-pass"
    mint.env["MINT_CONTROL_DB_PASSWORD"] = "control-pass"
    code, _, err = mint.run("init")
    assert code == 0 and "mint_plugin_app" in err and "mint_control_app" in err
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        members = {r[0] for r in conn.execute(
            "SELECT m.rolname FROM pg_auth_members a JOIN pg_roles m ON m.oid = a.member"
            " JOIN pg_roles g ON g.oid = a.roleid WHERE g.rolname IN ('mint_plugin','mint_control')"
        )}
    assert {"mint_plugin_app", "mint_control_app"} <= members


def test_bootstrap_once_then_every_command_needs_a_valid_token(mint):
    token = bootstrap(mint)
    code, _, err = mint.run("operator", "bootstrap", "--name", "b2", "--user-id", "human-1")
    assert code == 1 and "이미 있어" in err
    code, _, err = mint.run("org", "add", "x", "--name", "X")
    assert code == 4 and "필요" in err
    code, _, err = mint.run("org", "add", "x", "--name", "X", token="mint_wrong")
    assert code == 4 and "올바르지" in err
    code, _, _ = mint.run("org", "add", "x", "--name", "X", token=token)
    assert code == 0


def test_role_checks_follow_the_command_table(mint):
    boss = bootstrap(mint)
    viewer = mint.token(mint.run("operator", "add", "eye", "--role", "viewer", token=boss)[1])
    approver = mint.token(mint.run("operator", "add", "ap", "--role", "approver",
                                   "--user-id", "human-1", token=boss)[1])
    for command in COMMANDS:
        if command.unauthenticated:
            continue
        for role, token in ((OperatorRole.VIEWER, viewer), (OperatorRole.APPROVER, approver)):
            if role in command.roles:
                continue
            argv = _minimal_argv(command.path)
            code, _, err = mint.run(*argv, token=token)
            assert code == 4, (command.name, role, err)
            assert "역할로 실행할 수 없습니다" in err
    assert mint.run("ledger", "list", token=viewer)[0] == 0
    assert mint.run("org", "add", "o", "--name", "O", token=viewer)[0] == 4
    assert mint.run("org", "add", "o", "--name", "O", token=approver)[0] == 4


def _minimal_argv(path):
    """권한 검사가 인자 검사보다 앞서므로 인자는 형식만 맞으면 된다."""
    parser = cli.build_parser()
    required = {
        "--role": "viewer", "--relation": "r", "--scope": "key", "--scope-id": "s",
        "--tools": "t", "--valid-until": FAR_FUTURE, "--basis": "b", "--requested-by": "u",
        "--reason": "r", "--org": "o", "--server": "s", "--purpose": "p",
        "--principal-type": "user",
        "--principal-id": "p", "--tool": "t", "--args-fp": "0" * 64, "--user": "u",
        "--data-scope": "d", "--text-version": "v", "--evidence-ref": "e",
        "--evidence-sha256": "0" * 64, "--kind": "provider", "--value": "v", "--name": "n",
        "--team": "t", "--catalog-sha256": "0" * 64, "--bundle-sha256": "0" * 64,
        "--intake": "i",
        "--data-grade": "internal", "--allowed-resources": "[]", "--provider": "p",
        "--owner": "o", "--credential-notice": "n", "--revocation-record": "r",
        "--audit-access-days": "1", "--data-return-terms": "t", "--requester": "u",
        "--contract": "c.json",
    }
    argv = list(path)
    leaf = parser
    for part in path:
        leaf = next(a for a in leaf._actions if hasattr(a, "choices") and a.choices).choices[part]
    for action in leaf._actions:
        if action.option_strings and action.required and action.option_strings[0] in required:
            argv += [action.option_strings[0], required[action.option_strings[0]]]
        elif not action.option_strings and action.dest not in ("help",):
            argv.append(list(action.choices)[0] if action.choices else "x")
    for group in leaf._mutually_exclusive_groups:
        if group.required:
            argv += [group._group_actions[0].option_strings[0], "x"]
    return argv


def test_expired_and_unauthorized_tokens_exit_with_four(mint):
    boss = bootstrap(mint)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute("UPDATE mint.operators SET expires_at = now() - interval '1 second'")
        conn.commit()
    assert mint.run("ledger", "list", token=boss)[0] == 4


def test_token_file_option(mint):
    boss = bootstrap(mint)
    path = mint.tmp / "token"
    path.write_text(boss + "\n", encoding="utf-8")
    code, _, _ = mint.run("--token-file", str(path), "ledger", "list")
    assert code == 0
    code, _, err = mint.run("--token-file", str(mint.tmp / "none"), "ledger", "list")
    assert code == 4 and "토큰 파일" in err


def test_full_activation_path_through_the_cli(mint):
    boss = bootstrap(mint)
    appr = mint.token(mint.run("operator", "add", "ap", "--role", "approver", "--user-id",
                               "human-1", token=boss)[1])
    assert mint.run("org", "add", "acme", "--name", "ACME", token=boss)[0] == 0
    assert mint.run("org", "bind", "--org", "acme", "--user", "human-1", token=boss)[0] == 0
    code, _, err = mint.run("server", "register", "ctl-everything", token=boss)
    assert code == 1 and "--url" in err
    assert mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp",
                    token=boss)[0] == 0
    code, out, _ = mint.run("relation", "add", "--org", "acme", "--server", "ctl-everything",
                            "--purpose", "ops", token=boss)
    relation = out.strip()
    # 신청자와 승인자가 같은 사용자이면 거부, --second-approver로 다른 사용자가 확인하면 허용
    args = ["approve", "--relation", relation, "--scope", "key", "--scope-id", GOOD_KEY,
            "--tools", "echo", "--valid-until", FAR_FUTURE, "--basis", "근거",
            "--requested-by", "human-1"]
    code, _, err = mint.run(*args, token=appr)
    assert code == 1 and "--second-approver" in err
    boss_file = mint.tmp / "boss"
    boss_file.write_text(boss, encoding="utf-8")
    code, out, _ = mint.run(*args, "--second-approver", f"@{boss_file}", token=appr)
    assert code == 0, out
    code, out, _ = mint.run("ledger", "list", "--json", "--kind", "server_approved", token=boss)
    assert code == 0 and json.loads(out)["events"][0]["kind"] == "server_approved"
    code, out, _ = mint.run("revoke", "not-a-uuid", "--reason", "r", token=appr)
    assert code == 1  # 잘못된 식별자는 데이터베이스 오류로 거부된다


def test_settings_and_org_commands(mint):
    boss = bootstrap(mint)
    run = lambda *a: mint.run(*a, token=boss)  # noqa: E731
    assert run("org", "add", "o1", "--name", "O1")[0] == 0
    assert run("org", "bind", "--org", "o1", "--team", "t1")[0] == 0
    code, _, err = run("org", "bind", "--org", "default", "--team", "t1")
    assert code == 1 and "이미 조직 o1" in err
    assert run("org", "unbind", "--team", "t1")[0] == 0
    assert run("settings", "default-org", "--org", "o1")[0] == 0
    assert run("settings", "default-org", "--clear")[0] == 0
    mint.env["MINT_MODE"] = "observe"
    assert run("settings", "mode", "observe")[0] == 0
    observable = run("settings", "observable", "--reasons", "APPROVAL_ABSENT", "--policy-ids", "R1")
    assert observable[0] == 0
    code, _, err = run("settings", "observable", "--reasons", "DENIED")
    assert code == 1 and "전환할 수 없는" in err
    mint.env["MINT_MODE"] = "enforce"
    code, _, err = run("settings", "mode", "observe")
    assert code == 1 and "MINT_MODE" in err
    code, out, _ = run("status")
    assert code == 0 and "모드: enforce (저장 observe, 환경 상한 enforce)" in out
    code, out, _ = run("status", "--json")
    info = json.loads(out)
    assert info["mode"]["effective"] == "enforce" and info["policy_version"] is None


def test_policy_activate_needs_a_valid_bundle_source_and_engine_address(mint, tmp_path):
    boss = bootstrap(mint)
    code, _, err = mint.run("policy", "activate", "v1", "--policy-root", str(tmp_path),
                            token=boss)
    assert code == 1 and "--opa-url" in err
    code, _, err = mint.run("policy", "activate", "v1", "--policy-root", str(tmp_path),
                            "--opa-url", "http://opa.test:8181", token=boss)
    assert code == 1 and "정책 번들이 올바르지" in err


def test_init_writes_the_default_snippet_path_and_reports_json(mint):
    code, out, _ = mint.run("--json", "init", "--secrets-file", str(mint.tmp / "secrets.env"))
    result = json.loads(out)
    assert code == 0 and result["ok"] is True and result["command"] == "init"
    assert result["snippet_path"] == "config/litellm.mint.yaml"
    assert (mint.tmp / "config" / "litellm.mint.yaml").is_file()
    assert result["migrations"] == []  # 시험용 데이터베이스는 이미 최신이다
    assert result["fingerprint_key_created"] is True
    assert "MINT_FINGERPRINT_KEY=" in (mint.tmp / "secrets.env").read_text(encoding="utf-8")
    assert result["fingerprint_key_file"] == (mint.tmp / "secrets.env").as_posix()
    assert [e["kind"] for e in result["events"]] == [
        "settings_changed", "org_created", "settings_changed", "settings_changed"]


def test_json_output_names_the_created_object_version_and_event_keys(mint):
    code, out, _ = mint.run("init", "--json")
    assert code == 0
    code, out, _ = mint.run("operator", "bootstrap", "--name", "boss", "--user-id", "human-2",
                            "--json")
    result = json.loads(out)
    assert result["token"].startswith("mint_") and result["id"] == "boss"
    assert result["state_version"] == 1
    assert result["events"][0]["source_key"] == "operator:boss:1:operator_added"
    boss = result["token"]
    run = lambda *a: json.loads(mint.run(*a, "--json", token=boss)[1])  # noqa: E731
    org = run("org", "add", "acme", "--name", "ACME")
    mint.run("org", "bind", "--org", "acme", "--user", "human-1", token=boss)
    assert (org["id"], org["state_version"], org["events"][0]["kind"]) == ("acme", 1, "org_created")
    mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp", token=boss)
    relation = run("relation", "add", "--org", "acme", "--server", "ctl-everything",
                   "--purpose", "ops")
    assert relation["id"] == relation["events"][0]["entity_id"]
    assert relation["events"][0]["source_key"] == f"relation:{relation['id']}:1:relation_created"
    appr = mint.token(mint.run("operator", "add", "ap", "--role", "approver", "--user-id",
                               "human-1", token=boss)[1])
    approval = json.loads(mint.run(
        "approve", "--relation", relation["id"], "--scope", "key", "--scope-id", GOOD_KEY,
        "--tools", "echo", "--valid-until", FAR_FUTURE, "--basis", "b", "--requested-by", "x",
        "--json", token=appr)[1])
    assert [e["kind"] for e in approval["events"]] == ["approval_granted", "server_approved"]
    assert approval["id"] == approval["events"][0]["entity_id"]
    assert approval["state_version"] == 1
    revoked = run("revoke", approval["id"], "--reason", "r", "--deny")
    assert [e["kind"] for e in revoked["events"]] == ["approval_revoked", "denial_created"]
    assert revoked["id"] == approval["id"] and revoked["state_version"] == 2
    listed = run("ledger", "list", "--limit", "3")
    assert listed["ok"] is True and len(listed["events"]) == 3
    assert {"event_id", "kind", "source_key", "actor", "payload"} <= set(listed["events"][0])


def test_json_flag_is_accepted_before_the_command_too(mint):
    boss = bootstrap(mint)
    code, out, _ = mint.run("--json", "ledger", "list", token=boss)
    assert code == 0 and json.loads(out)["ok"] is True


def test_check_exits_nonzero_on_required_violations_and_prints_levels(mint):
    boss = bootstrap(mint)
    config = mint.tmp / "config.yaml"
    mint.run("init", "--out", str(config))
    code, out, err = mint.run("check", "--config", str(config), token=boss)
    assert code == 1 and "필수 설정 점검에 실패" in err
    assert "[실패] object_permission 서버 식별자 형식" in out
    assert "[경고] PROXY_BASE_URL" in out
    assert "  unbound_keys: 1" in out
    bad = mint.tmp / "bad.yaml"
    bad.write_text("general_settings: {}\n", encoding="utf-8")
    code, out, err = mint.run("check", "--config", str(bad), "--json", token=boss)
    result = json.loads(out)
    assert code == 1 and result["ok"] is False and "필수 설정 점검에 실패" in err
    assert {f["level"] for f in result["findings"]} >= {"FAIL"}
    env_file = mint.tmp / "litellm.env"
    env_file.write_text("PROXY_BASE_URL=https://g.test\nMCP_TRUSTED_REDIRECT_ORIGINS=https://a.test\n",
                        encoding="utf-8")
    code, out, _ = mint.run("check", "--config", str(config), "--env-file", str(env_file),
                            token=boss)
    assert "[경고] PROXY_BASE_URL" not in out


def test_check_without_a_config_file_fails(mint):
    boss = bootstrap(mint)
    code, out, _ = mint.run("check", token=boss)
    assert code == 1 and "[실패] LiteLLM 설정 파일" in out


def test_database_errors_are_reported_without_a_traceback(mint):
    boss = bootstrap(mint)
    code, _, err = mint.run("denial", "lift", "not-a-uuid", token=boss)
    assert code == 1 and "데이터베이스 오류" in err


def test_rerunning_init_keeps_a_cleared_default_org_and_other_changes(mint):
    boss = bootstrap(mint)
    run = lambda *a: mint.run(*a, token=boss)  # noqa: E731
    assert run("settings", "default-org", "--clear")[0] == 0
    assert run("settings", "observable", "--policy-ids", "R2")[0] == 0
    assert mint.run("init")[0] == 0
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        row = conn.execute(
            "SELECT default_org_id, observable_policy_ids FROM mint.settings"
        ).fetchone()
    assert row == (None, ["R2"])


def test_check_exits_with_three_when_a_required_row_cannot_be_verified(mint):
    boss = bootstrap(mint)
    config = mint.tmp / "config.yaml"
    mint.run("init", "--out", str(config))
    mint.env.pop("MINT_LITELLM_URL")  # 관리 API 없이 점검한다
    code, out, err = mint.run("--json", "check", "--config", str(config), token=boss)
    result = json.loads(out)
    assert code == 3 and result["ok"] is False and "서버 이름·별칭 유일성" in result["incomplete"]
    assert "필수 검증을 모두 수행하지 못했습니다" in err


def test_approve_flags_store_conditions_and_org_scope_is_refused(mint):
    boss = bootstrap(mint)
    appr = mint.token(mint.run("operator", "add", "ap", "--role", "approver", "--user-id",
                               "human-1", token=boss)[1])
    mint.run("org", "add", "acme", "--name", "ACME", token=boss)
    mint.run("org", "bind", "--org", "acme", "--user", "human-1", token=boss)
    mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp", token=boss)
    relation = mint.run("relation", "add", "--org", "acme", "--server", "ctl-everything",
                        "--purpose", "ops", token=boss)[1].strip()
    base = ["approve", "--relation", relation, "--tools", "echo", "--valid-until", FAR_FUTURE,
            "--basis", "b", "--requested-by", "x"]
    code, _, err = mint.run(*base, "--scope", "org", "--scope-id", "acme", token=appr)
    assert code == 1 and "MINT-UNSUPPORTED" in err and "team" in err
    code, out, _ = mint.run(
        *base, "--scope", "key", "--scope-id", GOOD_KEY, "--high-risk-tools", "rm,deploy",
        "--business-hours-only", "--business-hours", "Asia/Seoul,1-5,09:00,18:00",
        "--require-consent", "상담", "--json", token=appr)
    assert code == 0
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conditions = conn.execute("SELECT conditions FROM mint.approvals").fetchone()[0]
    assert conditions["high_risk_tools"] == ["deploy", "rm"]
    assert conditions["business_hours_only"] is True and conditions["require_consent"] == "상담"
    code, _, err = mint.run(*base, "--scope", "key", "--scope-id", GOOD_KEY,
                            "--business-hours", "Asia/Seoul,1-5,09:00,18:00", token=appr)
    assert code == 1 and "함께 써야" in err


def test_server_register_reads_the_url_from_the_litellm_config(mint):
    boss = bootstrap(mint)
    config = mint.tmp / "litellm.yaml"
    config.write_text(
        "mcp_servers:\n  everything:\n    server_id: ctl-everything\n"
        "    url: http://u.test/mcp\n", encoding="utf-8")
    code, out, _ = mint.run("--json", "server", "register", "ctl-everything", "--config",
                            str(config), token=boss)
    assert code == 0 and json.loads(out)["id"]
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        payload = conn.execute(
            "SELECT payload FROM mint.events WHERE kind = 'server_registered'"
        ).fetchone()[0]
    assert payload["url_source"] == "config_file"


def test_status_shows_observed_server_identity_mismatches_until_reregistered(mint):
    boss = bootstrap(mint)
    mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp", token=boss)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
            " VALUES (gen_random_uuid(), 'clitest', 'server_identity_mismatch_observed',"
            " 'selfcheck:run1:1:server_identity_mismatch_observed',"
            " '{\"server_id\": \"ctl-everything\", \"fields\": [\"url_sha256\", \"transport\"]}')"
        )
        conn.commit()
    code, out, _ = mint.run("--json", "status", token=boss)
    alerts = [a for a in json.loads(out)["alerts"]
              if a["kind"] == "server_identity_mismatch_observed"]
    assert [(a["server_id"], a["fields"]) for a in alerts] == [
        ("ctl-everything", ["url_sha256", "transport"])
    ]
    mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp", token=boss)
    code, out, _ = mint.run("--json", "status", token=boss)
    assert [a for a in json.loads(out)["alerts"]
            if a["kind"] == "server_identity_mismatch_observed"] == []


def test_init_keeps_an_existing_fingerprint_key(mint):
    path = mint.tmp / "secrets.env"
    mint.env["MINT_SECRETS_FILE"] = str(path)
    assert mint.run("init")[0] == 0
    first = path.read_text(encoding="utf-8")
    code, out, _ = mint.run("--json", "init")
    assert code == 0 and json.loads(out)["fingerprint_key_created"] is False
    assert path.read_text(encoding="utf-8") == first


def test_servers_without_a_url_are_refused(mint, stub):
    boss = bootstrap(mint)
    body = dict(json.loads(json.dumps(stub.routes[("/v1/mcp/server/ctl-everything",
                                                   frozenset())][1])), transport="stdio")
    stub.set("/v1/mcp/server/ctl-everything", body)
    code, _, err = mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp",
                            token=boss)
    assert code == 1 and "MINT-UNSUPPORTED" in err and "server_without_url" in err
    stub.set("/v1/mcp/server/ctl-everything", dict(body, transport="http", spec_path="spec.yaml"))
    code, _, err = mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp",
                            token=boss)
    assert code == 1 and "server_without_url" in err


def test_a_local_server_is_registered_from_a_contract_file_without_litellm(mint):
    boss = bootstrap(mint)
    path = mint.tmp / "contract.json"
    path.write_text(json.dumps({"executable": "/usr/bin/node", "argv": ["/opt/srv/index.js"],
                                "executable_sha256": "ab" * 32}), encoding="utf-8")
    code, _, err = mint.run("server", "register-local", "local-1", "--contract", str(path),
                            token=boss)
    assert code == 0, err
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        row = conn.execute(
            "SELECT identity_kind, url_sha256, status FROM mint.servers WHERE server_id = 'local-1'"
        ).fetchone()
    assert row == ("stdio", None, "awaiting_approval")
    path.write_text("{}", encoding="utf-8")
    code, _, err = mint.run("server", "register-local", "local-1", "--contract", str(path),
                            token=boss)
    assert code == 1 and "실행 계약" in err


def test_declared_file_access_flags_are_added_to_the_contract_and_bound_to_its_hash(mint):
    boss = bootstrap(mint)
    path = mint.tmp / "contract.json"
    path.write_text(json.dumps({"executable": "/usr/bin/node", "argv": ["/opt/srv/index.js"],
                                "executable_sha256": "ab" * 32}), encoding="utf-8")
    plain = ["server", "register-local", "local-1", "--contract", str(path)]
    assert mint.run(*plain, token=boss)[0] == 0
    code, _, err = mint.run(*plain, "--read", "/data", "--read-write", "/work", token=boss)
    assert code == 0, err
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        document = conn.execute(
            "SELECT payload -> 'exec_contract' FROM mint.events WHERE kind = 'server_registered'"
            " ORDER BY inserted_at DESC LIMIT 1"
        ).fetchone()[0]
    assert document["file_access"] == [{"path": "/data", "mode": "ro"},
                                       {"path": "/work", "mode": "rw"}]
    code, _, err = mint.run(*plain, "--read", "relative", token=boss)
    assert code == 1 and "실행 계약" in err


def test_ledger_list_finds_a_decision_by_its_error_reference(mint):
    boss = bootstrap(mint)
    first, second = "01a19fbd-0000-7000-8000-000000000001", "01a19fbd-0000-7000-8000-000000000002"
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        for invocation, attempt in ((first, 1), (first, 2), (second, 1)):
            conn.execute(
                "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
                " attempt_id, payload) VALUES (gen_random_uuid(), 'clitest', 'decision_evaluated',"
                " %s, %s, %s, '{}')",
                (f"call:{invocation}:{attempt}:decision_evaluated", invocation, attempt),
            )
        conn.commit()
    code, out, _ = mint.run("--json", "ledger", "list", "--decision-ref", f"{first}:2", token=boss)
    events = json.loads(out)["events"]
    assert code == 0 and [e["source_key"] for e in events] == [
        f"call:{first}:2:decision_evaluated"]
    code, out, _ = mint.run("--json", "ledger", "list", "--invocation-id", first, token=boss)
    assert len(json.loads(out)["events"]) == 2
    for bad in ("nonsense", f"{first}:0", f"{first}:x", "not-a-uuid:1"):
        code, _, err = mint.run("ledger", "list", "--decision-ref", bad, token=boss)
        assert code == 1 and "--decision-ref" in err
    code, _, err = mint.run("ledger", "list", "--decision-ref", f"{first}:1",
                            "--invocation-id", first, token=boss)
    assert code == 1 and "함께 쓸 수 없습니다" in err


def test_call_approval_request_computes_the_same_fingerprint_as_the_shared_function(mint):
    import base64

    from mint_litellm.types import fingerprint

    boss = bootstrap(mint)
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    mint.env["MINT_FINGERPRINT_KEY"] = key
    mint.env["MINT_FINGERPRINT_KEY_VERSION"] = "3"
    mint.run("org", "add", "acme", "--name", "ACME", token=boss)
    mint.run("server", "register", "ctl-everything", "--url", "http://u.test/mcp", token=boss)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES ('clitest', 'v1', %s, %s)", ("a" * 64, "a" * 64))
        conn.commit()
    arguments = {"b": 1, "a": "한글"}
    base = ["call-approval", "request", "--org", "acme", "--principal-type", "user",
            "--principal-id", "alice", "--server", "ctl-everything", "--tool", "echo",
            "--policy-version", "v1"]
    path = mint.tmp / "args.json"
    path.write_text(json.dumps(arguments, ensure_ascii=False), encoding="utf-8")
    for source in (["--arguments", json.dumps(arguments, ensure_ascii=False)],
                   ["--args-file", str(path)]):
        code, out, err = mint.run("--json", *base, *source, token=boss)
        assert code == 0, err
    expected = fingerprint.argument_fingerprint(arguments, b"k" * 32)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        rows = conn.execute("SELECT args_fp, fp_key_version FROM mint.call_approvals").fetchall()
    assert rows == [(expected, 3), (expected, 3)]
    # 계산된 값을 직접 넣어도 같고, 인자 원문과 함께 쓸 수는 없다
    with pytest.raises(SystemExit) as raised:
        mint.run(*base, "--args-fp", expected, "--arguments", "{}", token=boss)
    assert raised.value.code == 2
    code, _, err = mint.run(*base, "--args-fp", expected, "--fp-key-version", "5", token=boss)
    assert code == 0, err


def test_call_approval_request_needs_a_key_or_a_ready_fingerprint(mint):
    boss = bootstrap(mint)
    mint.env["MINT_SECRETS_FILE"] = str(mint.tmp / "absent.env")
    base = ["call-approval", "request", "--org", "acme", "--principal-type", "user",
            "--principal-id", "alice", "--server", "ctl-everything", "--tool", "echo"]
    code, _, err = mint.run(*base, "--arguments", "{}", token=boss)
    assert code == 1 and "지문 키" in err
    mint.env["MINT_FINGERPRINT_KEY"] = "short"
    code, _, err = mint.run(*base, "--arguments", "{}", token=boss)
    assert code == 1 and "인자 지문을 계산할 수 없습니다" in err
    code, _, err = mint.run(*base, "--arguments", "[1]", token=boss)
    assert code == 1


def activate_policy(mint, digest):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES ('clitest', 'v1', %s, %s)", ("a" * 64, digest))
        for status in ("staged", "active"):
            conn.execute("UPDATE mint.policy_versions SET status = %s, activated_at = now(),"
                         " activated_by = 'x' WHERE id = 'v1'", (status,))
        conn.commit()


def test_status_and_check_exit_codes_follow_the_policy_bundle_comparison(mint):
    from fake_opa import FakeOpa, expected_hash

    boss = bootstrap(mint)
    config = mint.tmp / "config.yaml"
    mint.run("init", "--out", str(config))
    activate_policy(mint, expected_hash())
    opa = FakeOpa()
    try:
        mint.env["MINT_OPA_URL"] = opa.url
        code, out, _ = mint.run("--json", "status", token=boss)
        assert code == 0 and json.loads(out)["ok"] is True
        assert json.loads(out)["policy_bundle"]["state"] == "match"
        code, out, _ = mint.run("--json", "check", "--config", str(config), token=boss)
        policy = [f for f in json.loads(out)["findings"] if f["item"] == "정책 번들 내용"]
        assert [f["level"] for f in policy] == ["OK"]

        opa.rules += "# 적재 뒤에 바뀐 규칙\n"  # 등록된 해시와 달라진다
        code, out, err = mint.run("--json", "status", token=boss)
        result = json.loads(out)
        assert code == 1 and result["ok"] is False and "다릅니다" in err
        assert result["policy_bundle"]["state"] == "mismatch"
        code, out, _ = mint.run("--json", "check", "--config", str(config), token=boss)
        policy = [f for f in json.loads(out)["findings"] if f["item"] == "정책 번들 내용"]
        assert code == 1 and [f["level"] for f in policy] == ["FAIL"]
    finally:
        opa.close()
    # 정책 엔진을 읽지 못하면 확인하지 못한 것이다
    mint.env["MINT_OPA_URL"] = "http://localhost:9"
    code, out, err = mint.run("--json", "status", token=boss)
    result = json.loads(out)
    assert code == 3 and result["ok"] is False and result["policy_bundle"]["state"] == "unverified"
    assert "확인하지 못했습니다" in err
    mint.env.pop("MINT_OPA_URL")
    code, out, _ = mint.run("--json", "status", token=boss)
    assert code == 3 and json.loads(out)["ok"] is False
    code, out, _ = mint.run("--json", "check", "--config", str(config), token=boss)
    result = json.loads(out)
    assert "정책 번들 내용" in result["incomplete"]


def test_status_without_an_active_policy_still_succeeds(mint):
    boss = bootstrap(mint)
    code, out, _ = mint.run("--json", "status", token=boss)
    assert code == 0 and json.loads(out)["ok"] is True


def test_the_fingerprint_key_file_must_be_private_and_the_arguments_file_readable(mint):
    import os

    from mint_litellm.control import secrets_file

    boss = bootstrap(mint)
    path = mint.tmp / "loose.env"
    secrets_file.ensure_fingerprint_key(path)
    mint.env["MINT_SECRETS_FILE"] = str(path)
    base = ["call-approval", "request", "--org", "acme", "--principal-type", "user",
            "--principal-id", "alice", "--server", "ctl-everything", "--tool", "echo"]
    code, _, err = mint.run(*base, "--arguments", "{}", token=boss)
    assert "0600" not in err  # 권한이 맞으면 키 때문에 거부하지 않는다(다른 이유로 실패할 수 있다)
    if os.name != "nt":
        path.chmod(0o644)
        code, _, err = mint.run(*base, "--arguments", "{}", token=boss)
        assert code == 1 and "0600" in err
    code, _, err = mint.run(*base, "--args-file", str(mint.tmp / "missing.json"), token=boss)
    assert code == 1 and "인자 지문을 계산할 수 없습니다" in err and "Traceback" not in err


def add_event(mint, kind, source_key, payload, seconds_ago=0):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, inserted_at,"
            " payload) VALUES (gen_random_uuid(), 'clitest', %s, %s,"
            " now() - make_interval(secs => %s), %s)",
            (kind, source_key, seconds_ago, json.dumps(payload)),
        )
        conn.commit()


def test_status_shows_the_latest_enforcement_state_per_worker(mint):
    boss = bootstrap(mint)
    code, out, _ = mint.run("--json", "status", token=boss)
    first = json.loads(out)
    assert code == 0 and first["enforcement"] == []
    assert "allowed_pre_hooks" not in first
    add_event(mint, "enforcement_unverified", "selfcheck:r1:1:enforcement_unverified",
              {"worker_id": "w1", "failed": [{"name": "OTHER", "detail": "x"}]}, 300)
    add_event(mint, "enforcement_verified", "selfcheck:r2:1:enforcement_verified",
              {"worker_id": "w1", "summary": {"1": "ok"}}, 200)
    add_event(mint, "enforcement_verified", "selfcheck:r3:1:enforcement_verified",
              {"worker_id": "w2"}, 100)
    add_event(mint, "enforcement_unverified", "selfcheck:r4:1:enforcement_unverified",
              {"worker_id": "w2", "failed": [{"item": 8, "name": "REQUIRED_SETTINGS",
                                              "detail": "bad row"}]}, 50)
    code, out, _ = mint.run("--json", "status", token=boss)
    states = {s["worker_id"]: s for s in json.loads(out)["enforcement"]}
    assert states["w1"]["passed"] is True
    assert states["w2"]["passed"] is False and "cause" not in states["w2"]
    assert states["w2"]["failed"][0]["detail"] == "bad row"
    assert states["w2"]["last_transition_at"] > states["w1"]["last_transition_at"]
    code, out, _ = mint.run("status", token=boss)
    assert "허용 사전 훅" not in out and "워커가 살아 있다는 뜻은 아님" in out
    assert "w1: 통과" in out and "w2: 실패 REQUIRED_SETTINGS" in out
    assert "REQUIRED_SETTINGS: bad row" in out
    # 가장 최근 전환만 보인다: w1은 실패 뒤 통과로 돌아왔으므로 통과이다
    add_event(mint, "enforcement_unverified", "selfcheck:r5:1:enforcement_unverified",
              {"worker_id": "w1", "failed": [{"name": "ROGUE", "detail": "r"}]}, 0)
    code, out, _ = mint.run("--json", "status", token=boss)
    states = {s["worker_id"]: s for s in json.loads(out)["enforcement"]}
    assert states["w1"]["passed"] is False and states["w1"]["failed"][0]["name"] == "ROGUE"
    assert "hooks" not in states["w1"]


def test_policy_activate_reports_the_restore_outcome_when_it_fails(mint, monkeypatch):
    from mint_litellm.control import policy_versions

    boss = bootstrap(mint)

    def failing(*args, **kwargs):
        raise policy_versions.ActivationError("정책 활성화에 실패했습니다: x", "restored")

    monkeypatch.setattr(policy_versions, "activate", failing)
    mint.env["MINT_OPA_URL"] = "http://opa.test:8181"
    code, out, err = mint.run("--json", "policy", "activate", "v9", token=boss)
    result = json.loads(out)
    assert code == 1 and result["ok"] is False and result["restore_outcome"] == "restored"
    assert "직전 번들: restored" in err


def test_policy_activate_success_reports_no_restore_outcome(mint, monkeypatch):
    from mint_litellm.control import policy_versions

    boss = bootstrap(mint)
    monkeypatch.setattr(policy_versions, "activate", lambda *a, **k: None)
    mint.env["MINT_OPA_URL"] = "http://opa.test:8181"
    code, out, _ = mint.run("--json", "policy", "activate", "v9", token=boss)
    result = json.loads(out)
    assert code == 0 and result["ok"] is True and result["restore_outcome"] is None


def test_status_keeps_every_worker_even_when_another_floods_the_log(mint):
    boss = bootstrap(mint)
    add_event(mint, "enforcement_verified", "selfcheck:old1:1:enforcement_verified",
              {"worker_id": "quiet"}, 5000)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, inserted_at,"
            " payload) SELECT gen_random_uuid(), 'clitest', 'enforcement_unverified',"
            " 'selfcheck:flood' || i || ':1:enforcement_unverified',"
            " now() - make_interval(secs => i % 3000), '{\"worker_id\": \"noisy\"}'::jsonb"
            " FROM generate_series(1, 1200) AS i"
        )
        conn.commit()
    code, out, _ = mint.run("--json", "status", token=boss)
    states = {s["worker_id"]: s for s in json.loads(out)["enforcement"]}
    assert set(states) == {"quiet", "noisy"} and states["quiet"]["passed"] is True


def test_status_survives_unexpected_failed_item_shapes_and_shows_run_and_time(mint):
    boss = bootstrap(mint)
    add_event(mint, "enforcement_unverified", "selfcheck:RUN-A:1:enforcement_unverified",
              {"worker_id": "w1", "failed": ["MCP_ORDER", 7, {"name": "X", "detail": "d"}]})
    add_event(mint, "enforcement_unverified", "selfcheck:RUN-B:1:enforcement_unverified",
              {"worker_id": "w2", "failed": "not a list"})
    code, out, _ = mint.run("--json", "status", token=boss)
    states = {s["worker_id"]: s for s in json.loads(out)["enforcement"]}
    assert code == 0
    assert [f["name"] for f in states["w1"]["failed"]] == ["MCP_ORDER", "7", "X"]
    assert states["w2"]["failed"] == []
    code, out, _ = mint.run("status", token=boss)
    assert code == 0 and "실행 RUN-A" in out and "실행 RUN-B" in out


def test_a_restart_with_the_same_worker_id_is_one_line_with_the_latest_run(mint):
    boss = bootstrap(mint)
    add_event(mint, "enforcement_verified", "selfcheck:FIRST:1:enforcement_verified",
              {"worker_id": "host:1"}, 100)
    add_event(mint, "enforcement_unverified", "selfcheck:SECOND:1:enforcement_unverified",
              {"worker_id": "host:1", "failed": [{"name": "ROGUE", "detail": "r"}]}, 10)
    code, out, _ = mint.run("--json", "status", token=boss)
    states = json.loads(out)["enforcement"]
    assert len(states) == 1 and states[0]["run_id"] == "SECOND" and states[0]["passed"] is False


def test_ledger_list_marks_the_final_attempt_and_shows_reason_and_previous_attempt(mint):
    boss = bootstrap(mint)
    first = "01a19fbd-0000-7000-8000-0000000000a1"
    second = "01a19fbd-0000-7000-8000-0000000000a2"
    stop = {"status": "stop", "reason_code": "CANCELLED"}
    rows = (
        (first, 1, "decision_evaluated", {}),
        (first, 2, "decision_evaluated",
         {"original_decision_ref": f"{first}:1", "stop": stop}),
        (second, 1, "decision_evaluated", {}),
    )
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        for invocation, attempt, kind, payload in rows:
            conn.execute(
                "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
                " attempt_id, payload) VALUES (gen_random_uuid(), 'clitest', %s, %s, %s, %s, %s)",
                (kind, f"call:{invocation}:{attempt}:{kind}", invocation, attempt,
                 json.dumps(payload)),
            )
        conn.commit()
    code, out, _ = mint.run("--json", "ledger", "list", token=boss)
    final = {e["source_key"]: e["final"] for e in json.loads(out)["events"]
             if e["invocation_id"] in (first, second)}
    assert final == {f"call:{first}:1:decision_evaluated": False,
                     f"call:{first}:2:decision_evaluated": True,
                     f"call:{second}:1:decision_evaluated": True}
    code, out, _ = mint.run("ledger", "list", "--invocation-id", first, token=boss)
    lines = {line.split("\t")[3]: line for line in out.strip().splitlines()}
    latest = lines[f"call:{first}:2:decision_evaluated"]
    assert latest.endswith("\t최종") and "사유 CANCELLED" in latest
    assert f"이전 시도 {first}:1" in latest
    assert "최종" not in lines[f"call:{first}:1:decision_evaluated"]


def test_init_creates_worker_and_staff_login_roles_when_passwords_are_given(mint):
    mint.env["MINT_WORKER_DB_PASSWORD"] = "worker-pass"
    mint.env["MINT_STAFF_DB_PASSWORD"] = "staff-pass"
    try:
        code, _, err = mint.run("init")
        assert code == 0 and "mint_worker_app" in err and "mint_staff_app" in err
        with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
            groups = {
                (r[0], r[1])
                for r in conn.execute(
                    "SELECT m.rolname, g.rolname FROM pg_auth_members a"
                    " JOIN pg_roles m ON m.oid = a.member JOIN pg_roles g ON g.oid = a.roleid"
                    " WHERE m.rolname IN ('mint_worker_app', 'mint_staff_app')"
                )
            }
        assert groups == {
            ("mint_worker_app", "mint_control"),
            ("mint_worker_app", "mint_worker"),
            ("mint_worker_app", "mint_sealer"),
            ("mint_staff_app", "mint_staff"),
        }
    finally:
        with psycopg.connect(mint.env["MINT_DATABASE_URL"], autocommit=True) as conn:
            for login in ("mint_worker_app", "mint_staff_app"):
                conn.execute(f'DROP OWNED BY "{login}"')
                conn.execute(f'DROP ROLE IF EXISTS "{login}"')


def test_init_fix_config_adds_the_missing_modes_once_and_refuses_what_it_cannot_edit(mint):
    config = mint.tmp / "litellm.config.yaml"
    config.write_text(
        "guardrails:\n  - guardrail_name: mint\n    litellm_params:\n"
        "      guardrail: mint_litellm.plugin.guardrail.MintGuardrail\n"
        "      mode: [pre_mcp_call, post_mcp_call]\n      default_on: true\n",
        encoding="utf-8", newline="\n",
    )
    code, _, err = mint.run("init", "--fix-config", str(config))
    assert code == 0 and "pre_call" in err and "mode" in err
    assert "mode: [pre_mcp_call, post_mcp_call, pre_call]" in config.read_text(encoding="utf-8")
    assert len(list(mint.tmp.glob("litellm.config.yaml.bak-*"))) == 1
    code, _, err = mint.run("init", "--fix-config", str(config))
    assert code == 0 and len(list(mint.tmp.glob("litellm.config.yaml.bak-*"))) == 1
    config.write_text(
        "guardrails:\n  - guardrail_name: mint\n    litellm_params:\n"
        "      guardrail: mint_litellm.plugin.guardrail.MintGuardrail\n"
        "      mode:\n        - pre_mcp_call\n", encoding="utf-8", newline="\n",
    )
    code, _, err = mint.run("init", "--fix-config", str(config))
    assert code == 1 and "직접 고친 뒤" in err
