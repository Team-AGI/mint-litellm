import base64
from pathlib import Path

import pytest

from mint_litellm.plugin.config import PluginConfig
from mint_litellm.types.settings import Mode

KEY_TEXT = base64.urlsafe_b64encode(bytes(range(32))).decode()
BASE = {
    "MINT_INSTANCE_ID": "prod-1",
    "MINT_DATABASE_URL": "postgresql://mint@db/mint",
    "MINT_OPA_URL": "http://opa:8181",
}


def test_defaults():
    config = PluginConfig.from_env(BASE)
    assert config.instance_id == "prod-1"
    assert config.mode_ceiling is Mode.ENFORCE and config.required is True
    assert config.high_risk_tools == frozenset()
    assert config.buffer_dir == Path("/var/lib/mint/buffer")
    assert config.buffer_max_bytes == 50 * 1024 * 1024
    assert config.decision_budget_seconds == 0.3
    assert config.fingerprint_key is None and config.opa_url == "http://opa:8181"
    assert config.selfcheck_grace_seconds == 120.0 and config.gc_freeze is True


def test_default_result_limits_are_configurable_and_zero_turns_them_off():
    assert PluginConfig.from_env(BASE).default_max_result_bytes == 1024 * 1024
    assert PluginConfig.from_env(BASE).default_max_result_items == 1000
    env = {**BASE, "MINT_DEFAULT_MAX_RESULT_BYTES": "0", "MINT_DEFAULT_MAX_RESULT_ITEMS": "50"}
    got = PluginConfig.from_env(env)
    assert (got.default_max_result_bytes, got.default_max_result_items) == (0, 50)
    with pytest.raises(RuntimeError):
        PluginConfig.from_env({**BASE, "MINT_DEFAULT_MAX_RESULT_BYTES": "-1"})


def test_every_setting_can_be_given():
    env = {
        **BASE,
        "MINT_MODE": "Observe",
        "MINT_REQUIRED": "false",
        "MINT_HIGH_RISK_TOOLS": " delete_repo, , drop_table ",
        "MINT_BUFFER_DIR": "/data/buf",
        "MINT_BUFFER_MAX_BYTES": "2048",
        "MINT_DB_POOL_SIZE": "4",
        "MINT_DECISION_BUDGET_MS": "500",
        "MINT_FINGERPRINT_KEY": KEY_TEXT,
        "MINT_FINGERPRINT_KEY_VERSION": "3",
        "MINT_READINESS_URL": "http://localhost:4000/health/readiness",
        "MINT_SELFCHECK_GRACE_SECONDS": "30",
        "MINT_LOG_LEVEL": " debug ",
        "MINT_GC_FREEZE": "false",
    }
    config = PluginConfig.from_env(env)
    assert config.log_level == "DEBUG" and config.gc_freeze is False
    assert config.mode_ceiling is Mode.OBSERVE and config.required is False
    assert config.high_risk_tools == {"delete_repo", "drop_table"}
    assert config.buffer_dir == Path("/data/buf") and config.buffer_max_bytes == 2048
    assert config.db_pool_size == 4 and config.decision_budget_seconds == 0.5
    assert config.fingerprint_key == bytes(range(32)) and config.fingerprint_key_version == 3
    assert config.opa_url == "http://opa:8181" and config.selfcheck_grace_seconds == 30.0


@pytest.mark.parametrize(
    "override",
    [
        {"MINT_INSTANCE_ID": ""},
        {"MINT_INSTANCE_ID": "has space"},
        {"MINT_INSTANCE_ID": "a:b"},
        {"MINT_DATABASE_URL": " "},
        {"MINT_MODE": "audit"},
        {"MINT_REQUIRED": "maybe"},
        {"MINT_BUFFER_MAX_BYTES": "ten"},
        {"MINT_BUFFER_MAX_BYTES": "10"},
        {"MINT_DB_POOL_SIZE": "0"},
        {"MINT_DECISION_BUDGET_MS": "1"},
        {"MINT_FINGERPRINT_KEY": "short"},
        {"MINT_FINGERPRINT_KEY": "k" * 20},
        {"MINT_FINGERPRINT_KEY": "not base64url!" + "a" * 40},
        {"MINT_FINGERPRINT_KEY": ""},
        {"MINT_FINGERPRINT_KEY_VERSION": "0"},
        {"MINT_LOG_LEVEL": "verbose"},
        {"MINT_SELFCHECK_GRACE_SECONDS": "9"},
        {"MINT_SELFCHECK_GRACE_SECONDS": "601"},
        {"MINT_SELFCHECK_GRACE_SECONDS": "two minutes"},
    ],
)
def test_invalid_values_raise_runtime_error_only(override):
    # LiteLLM keeps starting without the guardrail when the constructor raises ValueError
    # or TypeError, so configuration problems must surface as RuntimeError.
    with pytest.raises(RuntimeError):
        PluginConfig.from_env({**BASE, **override})


@pytest.mark.parametrize("missing", ["MINT_INSTANCE_ID", "MINT_DATABASE_URL", "MINT_OPA_URL"])
def test_required_settings(missing):
    env = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(RuntimeError, match=missing):
        PluginConfig.from_env(env)


@pytest.mark.parametrize("text", ["1", "TRUE", "yes", "on"])
def test_truthy_required_values(text):
    assert PluginConfig.from_env({**BASE, "MINT_REQUIRED": text}).required is True


@pytest.mark.parametrize("seconds", ["10", "120", "600"])
def test_the_startup_grace_accepts_its_whole_range(seconds):
    config = PluginConfig.from_env({**BASE, "MINT_SELFCHECK_GRACE_SECONDS": seconds})
    assert config.selfcheck_grace_seconds == float(seconds)


def test_the_log_level_is_unset_by_default_and_blank_means_unset():
    assert PluginConfig.from_env(BASE).log_level is None
    assert PluginConfig.from_env({**BASE, "MINT_LOG_LEVEL": "  "}).log_level is None


def test_configuring_the_log_level_sets_one_stderr_handler_once():
    import logging

    from mint_litellm.plugin.config import configure_logging

    logger = logging.getLogger("mint_litellm")
    before = (logger.level, list(logger.handlers), logger.propagate)
    try:
        configure_logging(None)
        assert (logger.level, logger.handlers, logger.propagate) == (
            before[0],
            before[1],
            before[2],
        )
        configure_logging("DEBUG")
        configure_logging("DEBUG")
        assert logger.level == logging.DEBUG and not logger.propagate
        assert len(logger.handlers) == len(before[1]) + 1
        assert logging.getLogger("mint_litellm.guardrail").isEnabledFor(logging.DEBUG)
    finally:
        logger.setLevel(before[0])
        logger.handlers[:] = before[1]
        logger.propagate = before[2]


def test_shadow_evaluation_is_off_unless_an_address_is_given():
    off = PluginConfig.from_env({**BASE, "MINT_SHADOW_OPA_URL": " "})
    assert off.shadow_opa_url is None
    assert (off.shadow_sample_percent, off.shadow_max_per_second) == (100, 50)
    env = {**BASE, "MINT_SHADOW_OPA_URL": "http://opa-shadow:8181",
           "MINT_SHADOW_SAMPLE_PERCENT": "10", "MINT_SHADOW_MAX_PER_SECOND": "5"}
    got = PluginConfig.from_env(env)
    assert (got.shadow_opa_url, got.shadow_sample_percent, got.shadow_max_per_second) == (
        "http://opa-shadow:8181", 10, 5)
    for name, bad in (("MINT_SHADOW_SAMPLE_PERCENT", "0"), ("MINT_SHADOW_SAMPLE_PERCENT", "101"),
                      ("MINT_SHADOW_MAX_PER_SECOND", "0")):
        with pytest.raises(RuntimeError):
            PluginConfig.from_env({**BASE, name: bad})


def test_scan_max_chars_defaults_large_and_can_be_set():
    assert PluginConfig.from_env(BASE).scan_max_chars == 32 * 1024 * 1024
    assert PluginConfig.from_env({**BASE, "MINT_SCAN_MAX_CHARS": "5000"}).scan_max_chars == 5000
