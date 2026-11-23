"""운영 자기 점검: 문제 판별과 작업 등록."""

from types import SimpleNamespace

from mint_litellm.control import jobs
from mint_litellm.control import operational_checks as oc
from mint_litellm.control.litellm_admin import LiteLLMError

ROOMY = SimpleNamespace(free=1 << 40, total=1 << 41)
MINT = {"guardrail_name": "mint", "litellm_params": {"guardrail": "x.MintGuardrail"}}


class Fake:
    def __init__(self, rows=None, error=None):
        self.rows, self.error = rows or [], error

    def list_guardrails(self):
        if self.error:
            raise LiteLLMError(self.error)
        return self.rows


def test_a_healthy_stack_has_no_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(oc.shutil, "disk_usage", lambda p: ROOMY)
    assert set(oc.findings(Fake([MINT]), tmp_path).values()) == {None}


def test_connection_key_and_duplicate_guardrails_are_told_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(oc.shutil, "disk_usage", lambda p: ROOMY)
    assert oc.findings(Fake(error="연결할 수 없습니다"), tmp_path)["litellm"]
    key = oc.findings(Fake(error="읽을 수 없습니다(HTTP 401)"), tmp_path)
    assert key["key"] and key["litellm"] is None
    assert oc.findings(Fake([MINT, MINT]), tmp_path)["guardrail"]


def test_low_disk_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(oc.shutil, "disk_usage", lambda p: SimpleNamespace(free=10, total=1000))
    assert oc.findings(None, tmp_path)["disk"]


def test_the_check_runs_at_startup_and_every_five_minutes():
    assert "operational_check" in jobs.KINDS and "operational_check" in jobs.HANDLERS
    assert jobs.SCHEDULES["operational_check"](None) == 300
