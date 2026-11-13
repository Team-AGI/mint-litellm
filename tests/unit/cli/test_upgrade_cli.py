"""upgrade policy·upgrade report 명령. DB를 쓰는 시험은 MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json

import pytest

from mint_litellm import cli
from mint_litellm.plugin.policy import bundle as policy_bundle

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")

SHA = "b" * 64


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def test_report_says_nothing_is_left_on_a_clean_database_and_json_carries_the_list(mint):
    token = bootstrap(mint)
    code, out, err = mint.run("upgrade", "report", token=token)
    assert code == 0, err
    assert "사람이 정할 일: 없음" in out
    code, out, _ = mint.run("--json", "upgrade", "report", token=token)
    assert code == 0 and json.loads(out)["decisions"] == []


def fake_bundle(monkeypatch, sha=SHA):
    monkeypatch.setattr(
        policy_bundle, "prepare_bundle",
        lambda *a, **k: policy_bundle.PreparedBundle("probe", "c" * 64, sha, b""),
    )
    calls = []
    monkeypatch.setattr(cli, "_policy_activate", lambda run: calls.append(run.args.version))
    return calls


def set_active(mint, sha):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256,"
            " status) VALUES ('clitest', 'initial', %s, %s, 'validated')", (sha, "c" * 64))
        conn.execute("UPDATE mint.policy_versions SET status = 'staged'")
        conn.execute("UPDATE mint.policy_versions SET status = 'active', activated_at = now(),"
                     " activated_by = 'boss'")


def test_policy_activates_a_new_version_only_when_the_catalog_hash_changed(mint, monkeypatch):
    token = bootstrap(mint)
    calls = fake_bundle(monkeypatch)
    set_active(mint, "d" * 64)
    code, out, err = mint.run("upgrade", "policy", "--opa-url", "http://opa", token=token)
    assert code == 0, err
    assert calls == [f"catalog-{SHA[:12]}"] and "활성화했습니다" in out


def test_policy_leaves_an_unchanged_catalog_alone(mint, monkeypatch):
    token = bootstrap(mint)
    calls = fake_bundle(monkeypatch)
    set_active(mint, SHA)
    code, out, err = mint.run("upgrade", "policy", "--opa-url", "http://opa", token=token)
    assert code == 0, err
    assert calls == [] and "같습니다" in out


def test_policy_check_only_reports_the_change(mint, monkeypatch):
    token = bootstrap(mint)
    calls = fake_bundle(monkeypatch)
    set_active(mint, "d" * 64)
    code, out, _ = mint.run("upgrade", "policy", "--check", token=token)
    assert code == 0 and calls == [] and "활성화해야 합니다" in out
