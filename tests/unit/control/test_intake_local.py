"""단말 출처 신청의 검사 분기(가짜 행·가짜 묶음·가짜 검사 컨테이너)."""

import contextlib
import json
from types import SimpleNamespace

import pytest

from mint_litellm.control import intake_checks as checks
from mint_litellm.control import intake_jobs, packs

DIGEST = "ab" * 32
WIN_DIGEST = "ef" * 32
MANIFEST = {
    "entry": "pkg:main",
    "platform": {"python": "3.12"},
    "files": [{"name": "pkg-1-py3-none-any.whl", "sha256": "cd" * 32, "size": 10}],
}
SPEC = {
    "index": "pypi", "name": "pkg", "version": "1.0", "extras": [], "command": "pkg",
    "argv": ["--root", "/data"], "file_access": [{"path": "/data", "mode": "ro"}],
    "network": "hosts", "allowed_hosts": ["b.example", "a.example"], "env_names": [],
}
TOOL = {"name": "read", "description": "읽기", "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True}}
POLICY = checks.PolicyData(
    ("ignore previous",),
    {"data": {"internal": 1}, "action": {"read": 0, "write": 1, "delete": 2},
     "irreversible": ["delete"], "grades": ["low", "medium", "high"]},
    "f" * 64,
)
READY = {"credential_notice": "mail", "revocation_record": "log", "audit_access_days": 90}


class Fake:
    def __init__(self, spec=SPEC, existing=None):
        self.contract = {"id": "c1", "pack_spec": spec, "pack_sha256": DIGEST,
                         "pack_manifest": MANIFEST}
        self.existing = existing or {}
        self.records, self.stored, self.graded, self.updates = [], [], [], []
        self.outcomes = {}
        self.conn = SimpleNamespace(execute=lambda sql, args: self.updates.append(args))
        self.job = SimpleNamespace(
            conn=self.conn, instance_id="i", settings=SimpleNamespace(local_python="/opt/py3"),
            policy_data=SimpleNamespace(get=lambda *_: POLICY), checkpoint=lambda: None)
        self.row = {"id": "n1", "server_id": "s1", "org_id": "o", "data_grade": "internal",
                    "readiness": READY, "source": "endpoint"}

    def install(self, monkeypatch, build=None, inspect=None):
        fake_intakes = SimpleNamespace(
            deployment_candidate=lambda *_: self.contract,
            existing_check=lambda conn, inst, iid, name, attempt: self.existing.get(name),
            contract_binding=lambda *_: "bound",
            record_check=lambda ctx, row, attempt, name, out, bound: (
                self.records.append((name, out.result, out.reason)),
                self.outcomes.__setitem__(name, out)),
            store_candidates=lambda ctx, sid, defs: self.stored.append(defs) or True,
            store_grades=lambda ctx, sid, graded: self.graded.append(graded),
        )
        monkeypatch.setattr(intake_jobs, "intakes", fake_intakes)
        monkeypatch.setattr(intake_jobs, "fetchone", lambda *a, **k: None)
        monkeypatch.setattr(intake_jobs.source_scan, "request_scan",
                            lambda *a, **k: {"status": "ok", "files": 1})
        monkeypatch.setattr(intake_jobs.source_scan, "dependency_outcome",
                            lambda *a, **k: checks.Outcome("pass", None, "sca:osv"))
        monkeypatch.setattr(intake_jobs, "_allowlists", lambda *_: [])
        monkeypatch.setattr(intake_jobs.allowlist_domain, "ensure_defaults", lambda ctx: None)
        stored = [checks.tool_definition(TOOL)]
        monkeypatch.setattr(intake_jobs, "_stored_definitions", lambda *_: stored)
        monkeypatch.setattr(intake_jobs, "transact", lambda ctx: contextlib.nullcontext())
        monkeypatch.setattr(packs, "build_pack", build or (
            lambda *a, windows=False, **k: (WIN_DIGEST if windows else DIGEST, MANIFEST)))
        monkeypatch.setattr(
            intake_jobs.inspection, "inspect_pack",
            inspect or (lambda *a, **k: {"status": "ok", "complete": True, "tools": [TOOL]}))

    def run(self):
        intake_jobs._run_local_checks(self.job, SimpleNamespace(conn=self.conn), self.row, 1)
        return self.records


def test_all_six_checks_pass_and_pack_is_recorded(monkeypatch):
    fake = Fake()
    fake.install(monkeypatch)
    names = [name for name, _, _ in fake.run()]
    assert names == list(checks.LOCAL_CHECKS)
    assert {result for _, result, _ in fake.records} == {"pass"}
    assert [d["name"] for d in fake.stored[0]] == ["read"]
    digest, manifest, contract, *_ = fake.updates[0]
    assert digest == DIGEST and json.loads(manifest) == MANIFEST
    contract = json.loads(contract)
    assert contract["schema_version"] == 2 and contract["executable"] == "/opt/py3"
    assert "executable_sha256" not in contract and contract["identity_kind"] == "stdio"
    assert contract["pack"] == {"sha256": DIGEST, "runtime": "python3", "python": "3.12",
                                "entry": "pkg:main", "windows": {"sha256": WIN_DIGEST}}
    assert contract["allowed_hosts"] == ["a.example", "b.example"]
    assert contract["file_access"] == [{"path": "/data", "mode": "ro"}]


@pytest.mark.parametrize("change", [
    {"name": "bad name"}, {"version": ""}, {"command": "../x"}, {"argv": ["a"] * 33},
])
def test_shape_violation_fails_and_stops(monkeypatch, change):
    fake = Fake({**SPEC, **change})
    fake.install(monkeypatch)
    assert [(n, r) for n, r, _ in fake.run()] == [("exec_shape", "fail")]
    assert not fake.updates


def test_pack_failure_is_indeterminate_not_a_rejection(monkeypatch):
    def refuse(*args, **kwargs):
        raise packs.PackError("PACK_SDIST_ONLY")

    fake = Fake()
    fake.install(monkeypatch, build=refuse)
    result = {name: (r, why) for name, r, why in fake.run()}
    assert result["pack_build"] == ("indeterminate", "PACK_SDIST_ONLY")
    assert result["inspection"] == ("indeterminate", "PACK_UNAVAILABLE")
    assert "fail" not in {r for r, _ in result.values()}
    assert len(result) == len(checks.LOCAL_CHECKS) and not fake.stored and not fake.updates


def test_incomplete_inspection_stores_no_candidates(monkeypatch):
    fake = Fake()
    fake.install(monkeypatch, inspect=lambda *a, **k: {
        "status": "incomplete", "reason": "TIMEOUT", "tools": [], "complete": False})
    result = {name: (r, why) for name, r, why in fake.run()}
    assert result["inspection"] == ("indeterminate", "TIMEOUT")
    assert result["description_scan"][0] == "indeterminate"
    assert len(result) == len(checks.LOCAL_CHECKS) and not fake.stored


def test_a_failed_inspection_records_the_stage_exit_code_and_stderr_tail(monkeypatch):
    detail = {"stage": "start", "exit_code": 1, "stderr_tail": "ValueError: not set" + "z" * 3000}
    fake = Fake()
    fake.install(monkeypatch, inspect=lambda *a, **k: {
        "status": "failed", "reason": "INSPECTION_FAILED", "tools": [], "complete": False,
        "detail": detail})
    fake.run()
    assert fake.outcomes["inspection"].reason == "SERVER_START_FAILED"
    recorded = fake.outcomes["inspection"].inputs["detail"]
    assert (recorded["stage"], recorded["exit_code"]) == ("start", 1)
    assert len(recorded["stderr_tail"]) == 2048 and recorded["stderr_tail"].endswith("z")


def test_a_server_that_dies_on_a_library_error_is_reported_as_a_version_mismatch():
    tail = "Traceback...\nImportError: cannot import name 'McpError' from 'mcp.shared.exceptions'"
    out = checks.inspection_outcome({
        "status": "failed", "reason": "INSPECTION_FAILED",
        "detail": {"stage": "start", "exit_code": 1, "stderr_tail": tail}})
    assert out.reason == "SERVER_DEPS_MISMATCH" and tail in out.inputs["detail"]["stderr_tail"]
    later = checks.inspection_outcome({
        "status": "failed", "reason": "TIMEOUT",
        "detail": {"stage": "tools_list", "exit_code": None, "stderr_tail": tail}})
    assert later.reason == "TIMEOUT"


def test_a_malformed_detail_is_dropped_to_safe_values():
    out = checks.inspection_outcome({"status": "failed", "reason": "INSPECTION_FAILED",
                                     "detail": {"stage": "elsewhere", "exit_code": "x",
                                                "stderr_tail": 5}})
    assert out.inputs["detail"] == {"stage": None, "exit_code": None, "stderr_tail": ""}
    assert checks.inspection_outcome({"status": "failed"}).inputs == {}


def test_retry_skips_recorded_checks_and_reuses_the_pack(monkeypatch):
    fake = Fake(existing={"exec_shape": {"result": "pass"}, "pack_build": {"result": "pass"}})
    seen = []
    fake.install(monkeypatch, inspect=lambda digest, entry, argv: seen.append(
        (digest, entry, argv)) or {"status": "ok", "complete": True, "tools": [TOOL]})
    monkeypatch.setattr(packs, "build_pack", lambda *a, **k: pytest.fail("rebuilt"))
    assert [n for n, _, _ in fake.run()][0] == "inspection"
    assert seen == [(DIGEST, "pkg:main", ["--root", "/data"])]


def test_endpoint_intake_uses_local_checks_and_concludes(monkeypatch):
    calls = []
    row = {"id": "n1", "server_id": "s1", "source": "endpoint", "status": "received"}
    fake_intakes = SimpleNamespace(
        get=lambda ctx, target: {**row, "approve_when_ready": None},
        apply_deferred_approval=lambda ctx, target, litellm: None,
        begin_checking=lambda ctx, target: row,
        conclude=lambda ctx, target, needs_registry_credentials: calls.append(
            ("conclude", needs_registry_credentials)) or "indeterminate")
    monkeypatch.setattr(intake_jobs, "intakes", fake_intakes)
    monkeypatch.setattr(intake_jobs, "_context", lambda job: "ctx")
    monkeypatch.setattr(intake_jobs, "_run_local_checks", lambda *a: calls.append("local"))
    monkeypatch.setattr(intake_jobs, "_run_checks", lambda *a, **k: pytest.fail("remote"))
    job = SimpleNamespace(job={"target_ref": "n1", "idempotency_key": "intake_run:n1:1"},
                          litellm=None)
    intake_jobs.intake_run(job)
    assert calls == ["local", ("conclude", False)]


NPM_SPEC = {"index": "npm", "name": "@o/srv", "version": "1.2.3", "extras": [], "command": "srv",
            "integrity": "sha512-" + "A" * 86 + "==", "argv": ["/data"],
            "file_access": [{"path": "/data", "mode": "ro"}]}


def test_an_npm_request_gets_a_pack_less_contract_and_registry_based_supply_chain_checks(
        monkeypatch):
    fake = Fake(NPM_SPEC)
    fake.contract["pack_sha256"] = fake.contract["pack_manifest"] = None
    fake.install(monkeypatch, build=lambda *a, **k: pytest.fail("npm has no pack"))
    inventory = {"components": [{"name": "@o/srv", "version": "1.2.3", "integrity": None}],
                 "unresolved": 0}
    asked = []
    monkeypatch.setattr(intake_jobs.source_scan, "npm_inventory", lambda spec: inventory)
    monkeypatch.setattr(intake_jobs.source_scan, "request_scan",
                        lambda request, wait=None: asked.append(request) or {
                            "status": "error", "reason": "SCANNER_UNAVAILABLE"})
    monkeypatch.setattr(
        intake_jobs.source_scan, "dependency_outcome",
        lambda manifest, feed, client=None, npm=None: asked.append(npm) or checks.Outcome(
            "pass", None, "sca:osv"))
    result = {name: (r, why) for name, r, why in fake.run()}
    assert result["exec_shape"] == ("pass", None) and result["pack_build"] == ("pass", None)
    # npm은 묶음이 없어 도구 목록은 PC가 처음 띄울 때 받는다(재시도 대상이 아니다)
    assert result["inspection"] == ("indeterminate", "INSPECT_ON_FIRST_RUN")
    assert result["sbom"] == ("pass", None) and result["dependency_vulns"] == ("pass", None)
    assert asked[0]["kind"] == "npm" and asked[0]["integrity"] == NPM_SPEC["integrity"]
    assert asked[1] is inventory
    contract = json.loads(fake.updates[0][0])
    assert contract["schema_version"] == 3 and contract["npm"]["bin"] == "srv"
    assert contract["argv"] == ["-y", "@o/srv@1.2.3", "/data"] and "pack" not in contract


def test_a_dependency_without_a_windows_build_leaves_the_linux_pack_working(monkeypatch):
    def only_linux(*args, windows=False, **kwargs):
        if windows:
            raise packs.PackError("PACK_RESOLVE_FAILED")
        return DIGEST, MANIFEST

    fake = Fake()
    fake.install(monkeypatch, build=only_linux)
    assert {result for _, result, _ in fake.run()} == {"pass"}
    contract = json.loads(fake.updates[0][2])
    assert contract["pack"]["sha256"] == DIGEST
    assert contract["pack"]["windows"] == {"unavailable": True}


def test_the_windows_pack_is_built_from_the_same_spec(monkeypatch):
    seen = []

    def record(spec, allowlists, python="3.12", windows=False, **kwargs):
        seen.append((spec["name"], spec["version"], python, windows))
        return (WIN_DIGEST if windows else DIGEST), MANIFEST

    fake = Fake()
    fake.install(monkeypatch, build=record)
    fake.run()
    assert seen == [("pkg", "1.0", "3.12", False), ("pkg", "1.0", "3.12", True)]
