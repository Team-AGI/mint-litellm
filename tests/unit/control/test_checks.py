"""배포 점검의 등급별 출력. 관리 API 응답은 v1.106.6의 실제 응답 형태 고정값이다."""

import copy

import pytest
import yaml
from litellm_stub import GOOD_KEY, fixture, key_entry

from mint_litellm.control import checks, litellm_config
from mint_litellm.control.checks import Level
from mint_litellm.types.settings import OBSERVATION_ITEMS, SETTINGS_TABLE

ENV = {"PROXY_BASE_URL": "https://gateway.test", "MCP_TRUSTED_REDIRECT_ORIGINS": "https://app.test"}


def good_config() -> dict:
    text = litellm_config.snippet({"everything": ("ctl-everything", "http://u.test/mcp")},
                                  no_spend_logs=False)
    return yaml.safe_load(text)


def registered_guardrails() -> dict:
    body = copy.deepcopy(fixture("guardrails_registered"))
    body["guardrails"][0]["litellm_params"]["guardrail"] = litellm_config.GUARDRAIL_CLASS
    return body


@pytest.fixture
def healthy(stub, litellm):
    """등록 서버와 같은 서버만 있고 결속되지 않은 키·제외 키가 없는 LiteLLM."""
    keys = fixture("key_list_full")
    keys["keys"] = [key_entry("k-good")]
    stub.set("/key/list", keys)
    stub.set("/team/list", [])
    stub.set("/guardrails/list", registered_guardrails())
    stub.set("/v1/mcp/server", [fixture("server_get")])
    return litellm


def run(config, litellm, env=ENV, **kwargs):
    return checks.run_checks(config, env, litellm, compat_probe=lambda: [], **kwargs)


def levels(report) -> dict[str, list[Level]]:
    found: dict[str, list[Level]] = {}
    for f in report.findings:
        found.setdefault(f.item, []).append(f.level)
    return found


def test_a_generated_snippet_with_full_environment_passes_cleanly(healthy):
    report = run(good_config(), healthy)
    bad = [f for f in report.findings if f.level in (Level.FAIL, Level.WARN)]
    assert bad == []
    assert not report.failed


def test_every_settings_row_is_reported(healthy):
    report = run(good_config(), healthy)
    reported = {f.item for f in report.findings}
    expected = {r.key for r in SETTINGS_TABLE if r.observation_item is None
                or r.key == "enable_redis_auth_cache" or r.key == "사용자·팀에 결속되지 않은 키"}
    assert expected <= reported
    assert set(report.observations) == set(OBSERVATION_ITEMS)


@pytest.mark.parametrize(
    ("mutate", "item"),
    [
        (lambda c: c.pop("guardrails"), "guardrails[MINT]"),
        (lambda c: c["guardrails"][0]["litellm_params"].update(mode=["pre_mcp_call"]),
         "guardrails[MINT]"),
        (lambda c: c["guardrails"][0]["litellm_params"].update(
            mode=["pre_mcp_call", "post_mcp_call"]), "guardrails[MINT]"),
        (lambda c: c["guardrails"][0]["litellm_params"].update(default_on=False),
         "guardrails[MINT]"),
        (lambda c: c["litellm_settings"].update(callbacks=["x.plugin.MintLogger"]), "callbacks"),
        (lambda c: c["litellm_settings"].update(callbacks=["x.mint_logger"]), "callbacks"),
        (lambda c: c["mcp_servers"]["everything"].update(allow_all_keys=True),
         "mcp_servers.<이름>.allow_all_keys"),
        (lambda c: c["mcp_servers"]["everything"].pop("server_id"),
         "mcp_servers.<이름>.server_id"),
        (lambda c: c["general_settings"].pop("require_key_mcp_access_defined"),
         "require_key_mcp_access_defined"),
        (lambda c: c["general_settings"].update(store_prompts_in_spend_logs=True),
         "store_prompts_in_spend_logs"),
        (lambda c: c["litellm_settings"].update(user_url_validation=False),
         "user_url_validation"),
        (lambda c: c["general_settings"].update(supported_db_objects=["guardrails"]),
         "supported_db_objects"),
        (lambda c: c["general_settings"].pop("disable_env_credential_login"),
         "disable_env_credential_login"),
        (lambda c: c["litellm_settings"].update(user_url_allowed_hosts=["internal.test"]),
         "user_url_allowed_hosts"),
        (lambda c: c["litellm_settings"].update(ssl_verify=False), "ssl_verify"),
        (lambda c: c["mcp_servers"]["everything"].pop("rpm"), "mcp_servers.<이름>.rpm"),
        (lambda c: c["mcp_servers"]["everything"].update(max_concurrent_requests=0),
         "mcp_servers.<이름>.max_concurrent_requests"),
        (lambda c: c["mcp_servers"]["everything"].update(timeout=3600),
         "mcp_servers.<이름>.timeout"),
        (lambda c: c["mcp_servers"]["everything"].update(auth_type="oauth2"),
         "mcp_servers.<이름>.issuer"),
        (lambda c: c["mcp_servers"]["everything"].update(
            auth_type="oauth2", issuer="https://i.test"),
         "mcp_servers.<이름>.oauth_identity_binding.mode"),
        (lambda c: c["mcp_servers"]["everything"].update(
            auth_type="oauth2", issuer="https://i.test",
            oauth_identity_binding={"mode": "enforce"}),
         "mcp_servers.<이름>.upstream_resource"),
        (lambda c: c["mcp_servers"].update(
            second={**c["mcp_servers"]["everything"], "server_id": "ctl-second",
                    "authentication_token": "os.environ/SHARED"},
            everything={**c["mcp_servers"]["everything"],
                        "authentication_token": "os.environ/SHARED"}),
         "mcp_servers.<이름>.authentication_token"),
    ],
)
def test_required_violations_fail(healthy, mutate, item):
    config = good_config()
    mutate(config)
    report = run(config, healthy)
    assert report.failed
    assert Level.FAIL in levels(report)[item]


def test_required_environment_violation_fails(healthy):
    report = run(good_config(), healthy, env={**ENV, "LITELLM_STRICT_GUARDRAIL_MODES": "false"})
    assert Level.FAIL in levels(report)["LITELLM_STRICT_GUARDRAIL_MODES"]
    env_spend = {**ENV, "STORE_PROMPTS_IN_SPEND_LOGS": "true"}
    assert Level.FAIL in levels(run(good_config(), healthy, env=env_spend))[
        "store_prompts_in_spend_logs"]


@pytest.mark.parametrize(
    ("mutate", "item"),
    [
        (lambda c: c["litellm_settings"].pop("key_generation_settings"),
         "key_generation_settings.personal_key_generation.allowed_user_roles"),
        (lambda c: c["general_settings"].update(mcp_allow_all_keys_respects_mcp_scope=False),
         "mcp_allow_all_keys_respects_mcp_scope"),
        (lambda c: c["general_settings"].update(use_x_forwarded_for=True),
         "use_x_forwarded_for, mcp_trusted_proxy_ranges"),
    ],
)
def test_recommended_violations_warn_without_failing(healthy, mutate, item):
    config = good_config()
    mutate(config)
    report = run(config, healthy)
    assert Level.WARN in levels(report)[item]
    assert not report.failed


def test_missing_environment_recommendations_warn(healthy):
    report = run(good_config(), healthy, env={"LEGACY_MULTI_INSTANCE_RATE_LIMITING": "true"})
    found = levels(report)
    for item in ("PROXY_BASE_URL", "MCP_TRUSTED_REDIRECT_ORIGINS",
                 "LEGACY_MULTI_INSTANCE_RATE_LIMITING"):
        assert Level.WARN in found[item]
    assert not report.failed


def test_second_replica_needs_a_shared_auth_cache(healthy):
    assert Level.WARN in levels(run(good_config(), healthy, replicas=2))["enable_redis_auth_cache"]
    config = good_config()
    config["litellm_settings"]["enable_redis_auth_cache"] = True
    assert Level.OK in levels(run(config, healthy, replicas=2))["enable_redis_auth_cache"]
    assert run(config, healthy, replicas=2).observations["auth_cache_shared"] == "true"


def test_observation_items_report_values_and_do_not_fail(stub, litellm):
    stub.set("/guardrails/list", registered_guardrails())
    report = run(good_config(), litellm)  # 실제 키 목록: 결속 없는 키 1, 별칭 형식 권한 1
    assert report.observations["unbound_keys"] == 1
    assert report.observations["guardrail_optout_subjects"] == 0
    assert report.observations["spend_log_arguments_stored"] == "true"
    assert Level.WARN in levels(report)["사용자·팀에 결속되지 않은 키"]
    config = good_config()
    config["general_settings"]["disable_spend_logs"] = True
    assert run(config, litellm).observations["spend_log_arguments_stored"] == "false"


def test_optout_metadata_on_keys_and_teams_is_counted_and_warned(healthy, stub):
    keys = fixture("key_list_full")
    keys["keys"] = [
        {**key_entry("k-good"), "metadata": {"opted_out_global_guardrails": ["pii"]}},
        {**key_entry("k-unbound"), "user_id": "u", "metadata": {"disable_global_guardrails": True}},
    ]
    stub.set("/key/list", keys)
    teams = fixture("team_list")
    teams[0]["metadata"] = {"opted_out_global_guardrails": ["pii"]}
    stub.set("/team/list", teams)
    report = run(good_config(), healthy)
    assert report.observations["guardrail_optout_subjects"] == 3
    assert Level.INFO in levels(report)["가드레일 제외 대상"]


def test_alias_formatted_object_permission_fails_with_guidance(stub, litellm):
    stub.set("/guardrails/list", registered_guardrails())
    report = run(good_config(), litellm)
    assert report.failed
    message = next(f.message for f in report.findings
                   if f.item == "object_permission 서버 식별자 형식")
    assert "k-alias" in message and "everything" in message and "server_id" in message


def test_duplicate_server_names_fail(healthy, stub):
    entry = fixture("server_get")
    twin = {**entry, "server_id": "uuid-2", "server_name": "other", "alias": "everything"}
    stub.set("/v1/mcp/server", [entry, twin])
    report = run(good_config(), healthy)
    assert Level.FAIL in levels(report)["서버 이름·별칭 유일성"]
    assert "everything" in next(f.message for f in report.findings
                                if f.item == "서버 이름·별칭 유일성")


def test_names_that_differ_only_by_a_space_collide_like_the_runtime_check(healthy, stub):
    entry = fixture("server_get")
    first = {**entry, "server_id": "uuid-1", "server_name": "a b", "alias": None}
    second = {**entry, "server_id": "uuid-2", "server_name": "a_b", "alias": None}
    stub.set("/v1/mcp/server", [first, second])
    report = run(good_config(), healthy)
    assert Level.FAIL in levels(report)["서버 이름·별칭 유일성"]


def test_one_server_with_equal_name_and_alias_is_not_a_duplicate(stub, litellm):
    stub.set("/v1/mcp/server", fixture("server_list"))  # 하나의 서버가 이름과 별칭을 같게 가진다
    report = run(good_config(), litellm)
    assert Level.OK in levels(report)["서버 이름·별칭 유일성"]


def test_registered_servers_must_match_the_registry(healthy):
    from mint_litellm.types.decision import url_sha256

    good = {"server_id": "ctl-everything", "url_sha256": url_sha256("http://u.test/mcp"),
            "transport": "http", "auth_type": "none"}
    assert Level.OK in levels(run(good_config(), healthy, registered_servers=[good]))[
        "등록 서버의 계약 값"]
    for bad in ({**good, "transport": "sse"}, {**good, "auth_type": "bearer_token"},
                {**good, "server_id": "ghost"}):
        assert Level.FAIL in levels(run(good_config(), healthy, registered_servers=[bad]))[
            "등록 서버의 계약 값"]


def test_a_registered_server_missing_from_the_registry_blocks_only_when_it_is_approved(healthy):
    from mint_litellm.types.decision import url_sha256

    gone = {"server_id": "ghost", "url_sha256": url_sha256("http://u.test/mcp"),
            "transport": "http", "auth_type": "none"}

    def check(status):
        return run(good_config(), healthy, registered_servers=[{**gone, "status": status}])

    assert Level.FAIL in levels(check("approved"))["등록 서버의 계약 값"]
    suspended = check("suspended")
    assert Level.INFO in levels(suspended)["중지된 서버의 레지스트리 항목"]
    assert "ghost" in next(
        f.message for f in suspended.findings if f.item == "중지된 서버의 레지스트리 항목"
    )
    assert Level.FAIL not in levels(suspended).get("등록 서버의 계약 값", [])
    assert Level.FAIL not in levels(check("awaiting_approval")).get("등록 서버의 계약 값", [])


def test_registered_guardrail_must_match_the_running_one(healthy, stub):
    stub.set("/guardrails/list", fixture("guardrails_empty"))
    assert Level.FAIL in levels(run(good_config(), healthy))["guardrails[MINT]"]
    body = registered_guardrails()
    body["guardrails"][0]["litellm_params"]["default_on"] = False
    stub.set("/guardrails/list", body)
    assert any("default_on" in f.message for f in run(good_config(), healthy).findings)
    stub.set("/guardrails/list", fixture("guardrails_registered"))  # 다른 클래스
    findings = run(good_config(), healthy).findings
    assert any("MINT 가드레일이 아닙니다" in f.message for f in findings)


def test_compat_symbols_are_required_when_litellm_is_installed(healthy):
    report = checks.run_checks(good_config(), ENV, healthy, compat_probe=lambda: ["x.y"])
    assert Level.FAIL in levels(report)["호환 계층 비공개 심볼"]
    absent = checks.run_checks(good_config(), ENV, healthy, compat_probe=lambda: None)
    assert Level.SKIP in levels(absent)["호환 계층 비공개 심볼"] and not absent.failed
    assert absent.incomplete == ["호환 계층 비공개 심볼"]


def test_missing_config_file_and_management_api(litellm):
    report = checks.run_checks(None, ENV, None, compat_probe=lambda: [])
    assert report.failed and Level.FAIL in levels(report)["LiteLLM 설정 파일"]
    assert Level.SKIP in levels(report)["서버 이름·별칭 유일성"]
    assert report.observations.get("spend_log_arguments_stored") == "확인 불가"


def test_render_lists_levels_and_the_four_observation_items(healthy):
    text = run(good_config(), healthy).render()
    assert "[통과] callbacks" in text
    for name in OBSERVATION_ITEMS:
        assert f"  {name}: " in text


def test_key_list_uses_full_objects_and_follows_pages(stub, litellm):
    page1 = {"keys": [key_entry("k-good")], "total_count": 2, "current_page": 1, "total_pages": 2}
    page2 = {"keys": [key_entry("k-alias")], "total_count": 2, "current_page": 2, "total_pages": 2}
    stub.set("/key/list", page1, return_full_object="true", size="100", page="1")
    stub.set("/key/list", page2, return_full_object="true", size="100", page="2")
    keys = litellm.list_keys()
    assert [k["key_alias"] for k in keys] == ["k-good", "k-alias"]
    assert all("metadata" in k for k in keys)
    assert GOOD_KEY == keys[0]["token"]


def test_team_permissions_omitted_from_the_list_are_read_from_team_info(stub, litellm):
    """목록 응답에는 권한 객체가 생략되고 상세 응답에만 별칭 권한이 있다."""
    stub.set("/guardrails/list", registered_guardrails())
    keys = fixture("key_list_full")
    keys["keys"] = [key_entry("k-good")]
    stub.set("/key/list", keys)
    teams = fixture("team_list")
    assert teams[1]["object_permission"] is None and teams[1]["object_permission_id"]
    report = run(good_config(), litellm)
    message = next(f.message for f in report.findings
                   if f.item == "object_permission 서버 식별자 형식")
    assert "팀 team-op" in message or "팀 team-op: everything" in message


def test_database_servers_with_allow_all_keys_fail_the_check(healthy, stub):
    open_server = dict(fixture("server_get"), allow_all_keys=True, url=None)
    stub.set("/v1/mcp/server", [open_server])
    from mint_litellm.types.decision import url_sha256

    row = {"server_id": "ctl-everything", "url_sha256": url_sha256("http://u.test/mcp"),
           "transport": "http", "auth_type": "none"}
    report = run(good_config(), healthy, registered_servers=[row])
    assert report.failed
    assert any(f.item == "mcp_servers.<이름>.allow_all_keys" and f.level is Level.FAIL
               and "ctl-everything" in f.message for f in report.findings)


def test_an_unverifiable_server_url_is_not_reported_as_a_match(healthy):
    from mint_litellm.types.decision import url_sha256

    config = good_config()
    config["mcp_servers"] = {}
    row = {"server_id": "ctl-everything", "url_sha256": url_sha256("http://u.test/mcp"),
           "transport": "http", "auth_type": "none"}
    report = run(config, healthy, registered_servers=[row])
    contract = [f for f in report.findings if f.item == "등록 서버의 계약 값"]
    assert [f.level for f in contract] == [Level.SKIP]
    assert "URL을 확인하지 못했습니다" in contract[0].message
    # 설정 파일에 같은 서버의 URL이 있으면 그 값으로 확인한다.
    config["mcp_servers"] = {"x": {"server_id": "ctl-everything", "url": "http://u.test/mcp"}}
    ok = run(config, healthy, registered_servers=[row])
    assert [f.level for f in ok.findings if f.item == "등록 서버의 계약 값"] == [Level.OK]
    config["mcp_servers"]["x"]["url"] = "http://moved.test/mcp"
    bad = run(config, healthy, registered_servers=[row])
    assert bad.failed


def test_missing_management_api_leaves_required_rows_unverified(healthy):
    report = checks.run_checks(good_config(), ENV, None, compat_probe=lambda: [])
    assert not report.failed
    assert set(report.incomplete) == {"서버 이름·별칭 유일성", "guardrails[MINT]"}


def test_the_fingerprint_key_passed_to_the_service_is_a_required_row(healthy, tmp_path):
    import base64

    good = base64.urlsafe_b64encode(b"k" * 32).decode()
    missing_file = {"MINT_SECRETS_FILE": str(tmp_path / "none.env")}

    def fingerprint(**extra):
        report = checks.run_checks(
            good_config(), {**ENV, **missing_file, **extra}, healthy,
            compat_probe=lambda: [], check_fingerprint=True,
        )
        return report, [f for f in report.findings if f.item == "MINT_FINGERPRINT_KEY"]

    report, found = fingerprint(MINT_FINGERPRINT_KEY=good, MINT_FINGERPRINT_KEY_VERSION="2")
    assert [f.level for f in found] == [Level.OK] and not report.failed
    report, found = fingerprint()
    assert [f.level for f in found] == [Level.FAIL] and report.failed
    report, found = fingerprint(MINT_FINGERPRINT_KEY="short")
    assert [f.level for f in found] == [Level.FAIL] and "형식" in found[0].message
    for version in ("x", "0"):
        report, found = fingerprint(MINT_FINGERPRINT_KEY=good, MINT_FINGERPRINT_KEY_VERSION=version)
        assert [f.level for f in found] == [Level.FAIL], version


def test_an_unreadable_fingerprint_file_is_unverified_and_incomplete(healthy, tmp_path):
    import os

    if os.name == "nt":
        pytest.skip("POSIX 파일 권한 시험")
    path = tmp_path / "secrets.env"
    path.write_text("MINT_FINGERPRINT_KEY=" + "A" * 43 + "\n", encoding="utf-8")
    path.chmod(0o644)
    report = checks.run_checks(good_config(), {**ENV, "MINT_SECRETS_FILE": str(path)}, healthy,
                               compat_probe=lambda: [], check_fingerprint=True)
    found = [f for f in report.findings if f.item == "MINT_FINGERPRINT_KEY"]
    assert [f.level for f in found] == [Level.SKIP]
    assert "MINT_FINGERPRINT_KEY" in report.incomplete and not report.failed


def test_a_readable_fingerprint_file_satisfies_the_row(healthy, tmp_path):
    from mint_litellm.control import secrets_file

    path = tmp_path / "secrets.env"
    secrets_file.ensure_fingerprint_key(path)
    report = checks.run_checks(good_config(), {**ENV, "MINT_SECRETS_FILE": str(path)}, healthy,
                               compat_probe=lambda: [], check_fingerprint=True)
    found = [f for f in report.findings if f.item == "MINT_FINGERPRINT_KEY"]
    assert [f.level for f in found] == [Level.OK]


def test_without_the_option_the_fingerprint_row_is_not_evaluated(healthy):
    report = run(good_config(), healthy)
    assert not [f for f in report.findings if f.item == "MINT_FINGERPRINT_KEY"]


def optout_keys(stub, *metadata):
    keys = fixture("key_list_full")
    base = key_entry("k-good")
    keys["keys"] = [{**base, "token": f"t{i}", "metadata": meta} for i, meta in enumerate(metadata)]
    stub.set("/key/list", keys)
    stub.set("/team/list", [])


def test_excluding_only_the_mint_guardrail_or_nothing_is_not_counted(healthy, stub):
    optout_keys(stub, {"opted_out_global_guardrails": ["mint"]},
                {"opted_out_global_guardrails": []}, {"disable_global_guardrails": False}, {})
    report = run(good_config(), healthy)
    assert report.observations["guardrail_optout_subjects"] == 0
    assert "가드레일 제외 대상" not in levels(report)


def test_the_mint_guardrail_name_comes_from_the_config(healthy, stub):
    optout_keys(stub, {"opted_out_global_guardrails": ["mint-prod"]},
                {"opted_out_global_guardrails": ["mint"]},
                {"opted_out_global_guardrails": ["pii", "mint-prod"]},
                {"disable_global_guardrails": True})
    config = good_config()
    config["guardrails"][0]["guardrail_name"] = "mint-prod"
    report = run(config, healthy)
    assert report.observations["guardrail_optout_subjects"] == 3  # 'mint'도 이 설정에서는 다른 이름
    message = next(f.message for f in report.findings if f.item == "가드레일 제외 대상")
    assert "다른 가드레일뿐입니다" in message and "호출할 수 없게" not in message


@pytest.mark.parametrize(
    "meta",
    [
        {"opted_out_global_guardrails": "mint"},  # 목록이 아니면 LiteLLM은 무시한다
        {"opted_out_global_guardrails": True},
        {"opted_out_global_guardrails": 5},
        {"opted_out_global_guardrails": {"mint": True}},
        {"opted_out_global_guardrails": None},
        {"opted_out_global_guardrails": [[1, 2], {"a": 1}, 7]},
        {"disable_global_guardrails": "true"},  # True일 때만 센다
        {"disable_global_guardrails": 1},
        {"disable_global_guardrails": "yes"},
        {"disable_global_guardrails": [True]},
        {"disable_global_guardrails": None},
        {"disable_global_guardrails": False},
    ],
)
def test_values_that_litellm_ignores_are_not_counted_and_never_raise(healthy, stub, meta):
    optout_keys(stub, meta)
    report = run(good_config(), healthy)
    assert report.observations["guardrail_optout_subjects"] == 0
    assert "가드레일 제외 대상" not in levels(report)


def test_only_a_list_naming_another_guardrail_or_true_is_counted(healthy, stub):
    optout_keys(stub, {"opted_out_global_guardrails": ["mint"]},  # MINT만이면 세지 않는다
                {"opted_out_global_guardrails": ["pii"]},
                {"opted_out_global_guardrails": ["x", [1], "mint"]},
                {"disable_global_guardrails": True},
                {"disable_global_guardrails": True, "opted_out_global_guardrails": "bad"})
    assert run(good_config(), healthy).observations["guardrail_optout_subjects"] == 4


def fingerprint_message(env, **kwargs):
    report = checks.run_checks(good_config(), env, None, compat_probe=lambda: [],
                               check_fingerprint=True, **kwargs)
    return report, next(f for f in report.findings if f.item == "MINT_FINGERPRINT_KEY")


def test_the_fingerprint_row_names_where_the_checked_value_came_from(tmp_path):
    import base64

    from mint_litellm.control import secrets_file

    good = base64.urlsafe_b64encode(b"k" * 32).decode()
    absent = {"MINT_SECRETS_FILE": str(tmp_path / "none.env")}
    _, found = fingerprint_message({**absent, "MINT_FINGERPRINT_KEY": good})
    assert "이 프로세스의 환경 변수" in found.message and "대조하지 않음" in found.message
    _, found = fingerprint_message(
        {**absent, "MINT_FINGERPRINT_KEY": good},
        env_file_keys=frozenset({"MINT_FINGERPRINT_KEY"}),
    )
    assert "--env-file" in found.message
    path = tmp_path / "secrets.env"
    secrets_file.ensure_fingerprint_key(path)
    _, found = fingerprint_message({"MINT_SECRETS_FILE": str(path)})
    assert f"비밀 파일 {path.as_posix()}" in found.message and "대조하지 않음" in found.message


def test_a_secret_file_with_invalid_utf8_is_unverified_not_a_crash(tmp_path):
    import os

    path = tmp_path / "secrets.env"
    path.write_bytes(b"MINT_FINGERPRINT_KEY=\xff\xfe\n")
    if os.name != "nt":
        path.chmod(0o600)
    report, found = fingerprint_message({"MINT_SECRETS_FILE": str(path)})
    assert found.level is Level.SKIP and "MINT_FINGERPRINT_KEY" in report.incomplete


def test_required_environment_policies_fail(healthy):
    wide = {**ENV, "MCP_TRUSTED_REDIRECT_ORIGINS": "https://app.test, *.com"}
    assert Level.FAIL in levels(run(good_config(), healthy, env=wide))["OAuth 리다이렉트 출처"]
    no_tls = {**ENV, "SSL_VERIFY": "false"}
    assert Level.FAIL in levels(run(good_config(), healthy, env=no_tls))["ssl_verify"]
    config = good_config()
    config["mcp_servers"]["everything"].update(auth_type="oauth2", issuer="https://i.test")
    config["mcp_servers"]["everything"]["oauth_identity_binding"] = {"mode": "enforce"}
    assert Level.OK in levels(run(config, healthy))["OAuth 리다이렉트 출처"]
    assert Level.FAIL in levels(run(config, healthy, env={}))["OAuth 리다이렉트 출처"]


def test_policy_status_lines_follow_the_settings_behind_each_policy(healthy):
    report = run(good_config(), healthy)
    assert set(report.policy_status().values()) == {"충족"}
    assert "  POL-R-13: 충족" in report.render()
    config = good_config()
    config["general_settings"]["disable_env_credential_login"] = False
    config["litellm_settings"]["ssl_verify"] = False
    status = run(config, healthy).policy_status()
    assert status["POL-R-13"] == status["POL-R-17"] == "미충족"
    assert status["POL-R-04"] == "충족"
    assert run(None, None).policy_status()["POL-R-17"] == "확인 불가"


def test_registered_local_servers_are_not_compared_with_the_registry(healthy):
    local = {"server_id": "local-1", "url_sha256": None, "transport": "stdio",
             "auth_type": "none", "identity_kind": "stdio", "status": "approved"}
    assert Level.OK in levels(run(good_config(), healthy, registered_servers=[local]))[
        "등록 서버의 계약 값"]
    clash = {**local, "server_id": "ctl-everything"}
    assert Level.FAIL in levels(run(good_config(), healthy, registered_servers=[clash]))[
        "등록 서버의 계약 값"]


def test_a_token_audience_setting_or_an_explicit_opt_out_satisfies_the_resource_row(healthy):
    for value in ("auto", "https://u.test/mcp", ""):
        config = good_config()
        config["mcp_servers"]["everything"].update(
            auth_type="oauth2", issuer="https://i.test",
            oauth_identity_binding={"mode": "enforce"}, upstream_resource=value)
        assert Level.OK in levels(run(config, healthy))["mcp_servers.<이름>.upstream_resource"]


@pytest.mark.parametrize(
    "update",
    [{"auth_type": "true_passthrough"}, {"auth_type": "oauth_delegate"},
     {"extra_headers": ["Authorization"]}, {"extra_headers": ["X-Api-Key"]}],
)
def test_a_server_that_forwards_the_callers_token_is_warned_about(healthy, update):
    config = good_config()
    config["mcp_servers"]["everything"].update(issuer="https://i.test", **update)
    found = levels(run(config, healthy))["mcp_servers.<이름>.auth_type"]
    assert Level.WARN in found and Level.FAIL not in found
    assert Level.OK in levels(run(good_config(), healthy))["mcp_servers.<이름>.auth_type"]


def test_db_registered_oauth_servers_without_upstream_resource_fail(healthy, stub):
    server = {**fixture("server_get"), "auth_type": "oauth2", "credentials": {"scopes": ["a"]}}
    stub.set("/v1/mcp/server", [server])
    item = checks.KEY_RESOURCE_DB
    assert Level.FAIL in levels(run(good_config(), healthy))[item]
    with_resource = {**server, "credentials": {"upstream_resource": "auto"}}
    stub.set("/v1/mcp/server", [with_resource])
    assert Level.OK in levels(run(good_config(), healthy))[item]
    delegated = {**server, "delegate_auth_to_upstream": True}
    stub.set("/v1/mcp/server", [delegated])
    assert Level.OK in levels(run(good_config(), healthy))[item]
