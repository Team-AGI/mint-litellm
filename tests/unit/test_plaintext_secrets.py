"""설정의 평문 비밀 탐지: 평문과 환경 참조, 중첩 헤더, 접속 주소, 값 비노출."""

import logging

import yaml

from mint_litellm.control import checks
from mint_litellm.control.checks import Level
from mint_litellm.plugin.selfcheck import warn_plaintext_secrets
from mint_litellm.types.plaintext_secrets import plaintext_secret_paths

SECRET = "sk-live-0123456789abcdef"


def test_literal_values_are_flagged_and_environment_references_are_not():
    config = {
        "model_list": [
            {"litellm_params": {"model": "gpt", "api_key": SECRET}},
            {"litellm_params": {"model": "gpt", "api_key": "os.environ/OPENAI_API_KEY"}},
        ],
        "general_settings": {"master_key": SECRET, "disable_env_credential_login": True},
        "mcp_servers": {"gh": {"url": "http://x/mcp", "auth_value": SECRET}},
        "litellm_settings": {"callbacks": ["a.b"], "client_secret": "os.environ/CS"},
    }
    assert plaintext_secret_paths(config) == [
        "model_list[0].litellm_params.api_key",
        "general_settings.master_key",
        "mcp_servers.gh.auth_value",
    ]


def test_nested_headers_are_found_by_header_name():
    config = {
        "mcp_servers": {
            "s": {
                "headers": {
                    "Authorization": f"Bearer {SECRET}",
                    "X-Api-Key": "os.environ/K",
                    "Accept": "x",
                }
            }
        }
    }
    assert plaintext_secret_paths(config) == ["mcp_servers.s.headers.Authorization"]


def test_database_url_is_flagged_only_when_it_carries_a_password():
    assert plaintext_secret_paths(
        {"general_settings": {"database_url": "postgresql://mint:hunter2@db:5432/mint"}}
    ) == ["general_settings.database_url"]
    for ok in ("postgresql://db:5432/mint", "postgresql://mint@db/mint", "os.environ/DATABASE_URL"):
        assert plaintext_secret_paths({"general_settings": {"database_url": ok}}) == []


def test_names_that_only_look_like_secrets_are_not_flagged():
    config = {
        "litellm_settings": {
            "max_tokens": 10,
            "token_url": "https://t",
            "tokens": 3,
            "password_hint_name": "x",
            "api_key": "",
            "master_key": None,
        }
    }
    assert plaintext_secret_paths(config) == []


def test_the_check_warns_with_paths_only_and_never_fails():
    config = {"general_settings": {"master_key": SECRET}}
    report = checks.run_checks(config, {}, None, compat_probe=lambda: [])
    found = [f for f in report.findings if f.item == checks.PLAINTEXT_SECRET_ITEM]
    assert [f.level for f in found] == [Level.WARN]
    assert "general_settings.master_key" in found[0].message and SECRET not in found[0].message
    clean = checks.run_checks(
        {"general_settings": {"master_key": "os.environ/M"}}, {}, None, compat_probe=lambda: []
    )
    assert [f.level for f in clean.findings if f.item == checks.PLAINTEXT_SECRET_ITEM] == [Level.OK]


def test_the_startup_warning_logs_paths_without_values(tmp_path, caplog):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"general_settings": {"master_key": SECRET}}), encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert warn_plaintext_secrets({"MINT_LITELLM_CONFIG": str(path)}) == [
            "general_settings.master_key"
        ]
    assert "general_settings.master_key" in caplog.text and SECRET not in caplog.text
    assert warn_plaintext_secrets({"MINT_LITELLM_CONFIG": str(tmp_path / "none.yaml")}) == []
    assert warn_plaintext_secrets({}) == []
