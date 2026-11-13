"""2단계 설정 검증: 필수 값 누락과 잘못된 값은 거부한다."""

import base64
from pathlib import Path

import pytest

from mint_litellm.control.errors import ControlError
from mint_litellm.control.stage2_config import Stage2Settings

KEY = base64.urlsafe_b64encode(b"k" * 32).decode()
OTHER = base64.urlsafe_b64encode(b"o" * 40).decode()
BASE = {"MINT_EXPORT_DIR": "/exports", "MINT_EXPORT_HMAC_KEY": KEY}


def test_defaults():
    s = Stage2Settings.from_env(BASE)
    assert s.export_dir == Path("/exports")
    assert s.export_hmac_key == b"k" * 32 and s.export_hmac_key_previous is None
    assert (s.sync_hold_window_seconds, s.worker_lease_seconds, s.reconcile_seconds) == (
        3600,
        60,
        300,
    )
    assert (s.observe_seconds, s.submission_poll_seconds, s.checkpoint_seconds) == (3600, 60, 600)
    assert (s.session_idle_seconds, s.session_absolute_seconds, s.session_verify_seconds) == (
        1800,
        28800,
        300,
    )
    assert s.webhook_urls == () and s.webhook_hmac_key is None
    assert (s.recert_days, s.recert_grace_days) == (90, 14)


def test_overrides_and_previous_key():
    s = Stage2Settings.from_env(
        {
            **BASE,
            "MINT_EXPORT_HMAC_KEY_PREVIOUS": OTHER,
            "MINT_OBSERVE_SECONDS": "60",
            "MINT_RECERT_DAYS": "30",
            "MINT_RECERT_GRACE_DAYS": "7",
            "MINT_WEBHOOK_URLS": "https://a.example/hook, https://b.example/hook",
            "MINT_WEBHOOK_HMAC_KEY": OTHER,
        }
    )
    assert s.export_hmac_key_previous == b"o" * 40
    assert s.observe_seconds == 60
    assert (s.recert_days, s.recert_grace_days) == (30, 7)
    assert s.webhook_urls == ("https://a.example/hook", "https://b.example/hook")


@pytest.mark.parametrize("drop", ["MINT_EXPORT_DIR", "MINT_EXPORT_HMAC_KEY"])
def test_missing_required_values_are_refused(drop):
    env = {k: v for k, v in BASE.items() if k != drop}
    with pytest.raises(ControlError, match=drop):
        Stage2Settings.from_env(env)
    with pytest.raises(ControlError, match=drop):
        Stage2Settings.from_env({**env, drop: "  "})


@pytest.mark.parametrize(
    "extra",
    [
        {"MINT_EXPORT_HMAC_KEY": base64.urlsafe_b64encode(b"s" * 31).decode()},
        {"MINT_EXPORT_HMAC_KEY": "not base64!"},
        {"MINT_EXPORT_HMAC_KEY_PREVIOUS": "short"},
        {"MINT_OBSERVE_SECONDS": "0"},
        {"MINT_OBSERVE_SECONDS": "19"},
        {"MINT_OBSERVE_SECONDS": "abc"},
        {"MINT_WORKER_LEASE_SECONDS": "-5"},
        {"MINT_WEBHOOK_URLS": "http://a.example/hook", "MINT_WEBHOOK_HMAC_KEY": KEY},
        {"MINT_WEBHOOK_URLS": "https://a.example/hook"},
        {"MINT_WEBHOOK_URLS": "https://a.example/hook", "MINT_WEBHOOK_HMAC_KEY": "short"},
        {"MINT_SESSION_IDLE_SECONDS": "9999", "MINT_SESSION_ABSOLUTE_SECONDS": "60"},
    ],
)
def test_invalid_values_are_refused(extra):
    with pytest.raises(ControlError):
        Stage2Settings.from_env({**BASE, **extra})


def test_webhook_key_is_not_required_without_urls():
    assert Stage2Settings.from_env({**BASE, "MINT_WEBHOOK_URLS": " "}).webhook_urls == ()


def test_staff_consent_ceiling_defaults_and_is_bounded():
    assert Stage2Settings.from_env(BASE).staff_consent_max_days == 90
    env = {**BASE, "MINT_STAFF_CONSENT_MAX_DAYS": "365"}
    assert Stage2Settings.from_env(env).staff_consent_max_days == 365
    for bad in ("0", "366", "abc", "-1"):
        with pytest.raises(ControlError):
            Stage2Settings.from_env({**BASE, "MINT_STAFF_CONSENT_MAX_DAYS": bad})


def test_the_control_instance_id_follows_the_plugin_identifier_rule():
    import pytest as _pytest

    from mint_litellm.control.config import ControlConfig

    assert ControlConfig.from_env({"MINT_INSTANCE_ID": "ok-1.a"}).instance_id == "ok-1.a"
    for bad in ("../x", "a/b", "a b", "-x", ""):
        with _pytest.raises(ControlError):
            ControlConfig.from_env({"MINT_INSTANCE_ID": bad})


def test_the_cache_sharing_check_counts_workers_as_well_as_replicas():
    from mint_litellm.control.config import ControlConfig

    assert ControlConfig.from_env({}).replicas == 1
    assert ControlConfig.from_env({"MINT_REPLICAS": "2", "MINT_LITELLM_WORKERS": "3"}).replicas == 6
