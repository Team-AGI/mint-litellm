import pytest

from mint_litellm import cli
from mint_litellm.control import approvals
from mint_litellm.control.errors import ControlError

FAR = "20" + "99-01-01"
BASE = [
    "approve",
    "--relation",
    "r",
    "--scope",
    "key",
    "--scope-id",
    "k",
    "--tools",
    "echo",
    "--valid-until",
    FAR,
    "--basis",
    "b",
    "--requested-by",
    "x",
]


def test_allowed_flags_repeat_and_reach_the_conditions():
    a = cli.build_parser().parse_args(
        [
            *BASE,
            "--allowed-host",
            "b.test",
            "--allowed-host",
            "a.test",
            "--allowed-path",
            "/srv/docs",
            "--allowed-arg-key",
            "repo",
            "--allowed-arg-key",
            "repo",
        ]
    )
    conditions = approvals.build_conditions(
        high_risk_tools=None,
        business_hours_only=False,
        business_hours=None,
        require_consent=None,
        allowed_hosts=a.allowed_host,
        allowed_paths=a.allowed_path,
        allowed_arg_keys=a.allowed_arg_key,
    )
    assert conditions == {
        "allowed_hosts": ["a.test", "b.test"],
        "allowed_paths": ["/srv/docs"],
        "allowed_arg_keys": ["repo"],
    }


def test_conditions_without_the_flags_are_unchanged():
    a = cli.build_parser().parse_args(BASE)
    assert (a.allowed_host, a.allowed_path, a.allowed_arg_key) == (None, None, None)
    assert (
        approvals.build_conditions(
            high_risk_tools=None,
            business_hours_only=False,
            business_hours=None,
            require_consent=None,
        )
        == {}
    )


def test_blank_allowed_values_are_rejected():
    with pytest.raises(ControlError, match="allowed-host"):
        approvals.build_conditions(
            high_risk_tools=None,
            business_hours_only=False,
            business_hours=None,
            require_consent=None,
            allowed_hosts=[" "],
        )


def _conditions(**kwargs):
    return approvals.build_conditions(
        high_risk_tools=None,
        business_hours_only=False,
        business_hours=None,
        require_consent=None,
        **kwargs,
    )


@pytest.mark.parametrize(
    "host", ["*", "com", "a..test", ".test", "a.test.", "*.com", "bad host.test", "", "-a.test"]
)
def test_bad_allowed_hosts_are_rejected(host):
    with pytest.raises(ControlError, match="allowed-host"):
        _conditions(allowed_hosts=[host])


@pytest.mark.parametrize("host", ["a.test", "*.a.test", "A.Test", "[::1]", "x-y_z.example.org"])
def test_good_allowed_hosts_are_accepted(host):
    assert _conditions(allowed_hosts=[host])["allowed_hosts"]


def test_literal_addresses_are_accepted_as_hosts():
    assert _conditions(allowed_hosts=["203" + ".0.113.5", "2001:db8::1"])


@pytest.mark.parametrize("path", ["docs", "./docs", "/srv/../etc", "", "C:docs"])
def test_bad_allowed_paths_are_rejected(path):
    with pytest.raises(ControlError, match="allowed-path"):
        _conditions(allowed_paths=[path])


@pytest.mark.parametrize("path", ["/srv/docs", "/", "C:/srv/docs", "C:" + chr(92) + "srv"])
def test_good_allowed_paths_are_accepted(path):
    assert _conditions(allowed_paths=[path])["allowed_paths"]


def test_response_scan_is_an_approval_condition_only_when_given():
    a = cli.build_parser().parse_args([*BASE, "--response-scan", "block"])
    assert _conditions(response_scan=a.response_scan) == {"response_scan": "block"}
    assert cli.build_parser().parse_args(BASE).response_scan is None
    assert _conditions() == {}
    with pytest.raises(ControlError, match="response-scan"):
        _conditions(response_scan="off")
