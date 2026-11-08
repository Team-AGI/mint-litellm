"""플러그인의 되돌림 감시: 주기 판정 결과를 메모리에 두고 호출은 그 값만 읽는다.
DB 조회는 가짜로 바꾸고 파일은 임시 디렉터리에 둔다."""

import asyncio

import pytest
from plugin_helpers import config, harness, request

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.restore_watch import RestoreWatch
from mint_litellm.restore import files, judge

KEY = b"k" * 32
KEY2 = b"j" * 32
INSTANCE = "inst-1"


class FakeDatabase:
    """``_row``만 쓰는 감시 시험용. 질의 순서: 2단계 확인, 사실 조회."""

    def __init__(self, applied=True, facts=None):
        self.applied = applied
        self.facts = facts or {"epoch": 5, "has_written": True, "has_negative_written": False,
            "missing": 0, "anchor_ok": True}
        self.queries: list[str] = []


class Watch(RestoreWatch):
    async def _row(self, sql, params):
        self.database.queries.append(sql)
        if "to_regclass" in sql:
            return {"ok": self.database.applied}
        return self.database.facts


def cfg(tmp_path, key=KEY, previous=None, export=True):
    base = config(tmp_path)
    from dataclasses import replace

    return replace(
        base,
        instance_id=INSTANCE,
        export_dir=(tmp_path / "export") if export else None,
        export_hmac_key=key,
        export_hmac_key_previous=previous,
    )


def write_latest(tmp_path, key=KEY, epoch=5, tail=None, seq=None):
    doc = {"format": 1, "instance_id": INSTANCE, "state_epoch": epoch, "to_seal_seq": seq,
           "tail_hash": tail, "written_at": "2026-01-01T00:00:00+00:00"}
    files.atomic_write(files.latest_path(tmp_path / "export", INSTANCE), files.sign(doc, key))


def run(coro):
    return asyncio.run(coro)


def decide(h):
    return run(evaluate_request(request(), h.deps))


def code(outcome) -> str:
    assert outcome.error is not None, "expected a block"
    return outcome.error.code


def test_a_one_stage_database_is_never_judged(tmp_path):
    watch = Watch(cfg(tmp_path), FakeDatabase(applied=False))
    assert run(watch.refresh()) is None
    assert watch.blocked_cause is None
    assert watch.database.queries == ["SELECT to_regclass('mint.exports') IS NOT NULL AS ok"]


def test_missing_export_config_on_a_two_stage_database_blocks(tmp_path):
    watch = Watch(cfg(tmp_path, key=None, export=False), FakeDatabase())
    run(watch.refresh())
    assert watch.blocked_cause == "export_config_missing"
    watch = Watch(cfg(tmp_path, key=KEY, export=False), FakeDatabase())
    run(watch.refresh())
    assert watch.blocked_cause == "export_config_missing"


def test_a_healthy_export_does_not_block_and_a_first_install_is_not_judged(tmp_path):
    watch = Watch(cfg(tmp_path), FakeDatabase(facts={"epoch": 5, "has_written": False,
                                                      "has_negative_written": False,
                                                      "missing": 0, "anchor_ok": True}))
    run(watch.refresh())
    assert watch.verdict.state == judge.SKIP and watch.blocked_cause is None
    write_latest(tmp_path)
    watch = Watch(cfg(tmp_path), FakeDatabase())
    run(watch.refresh())
    assert watch.verdict.state == judge.OK and watch.blocked_cause is None


def test_causes_follow_the_table(tmp_path):
    write_latest(tmp_path)
    ok = {"epoch": 5, "has_written": True, "has_negative_written": False,
            "missing": 0, "anchor_ok": True}
    bad = {**ok, "missing": 1}
    watch = Watch(cfg(tmp_path), FakeDatabase(facts=bad))
    run(watch.refresh())
    assert watch.blocked_cause is None  # 첫 불일치는 호출을 막지 않는다
    run(watch.refresh())
    assert watch.blocked_cause == "restore_pending"  # 두 번 연속
    watch.database.facts = ok
    run(watch.refresh())
    assert watch.blocked_cause is None  # 복원 뒤 바로 풀린다
    files.latest_path(tmp_path / "export", INSTANCE).unlink()
    run(watch.refresh())
    assert watch.blocked_cause == "export_missing"
    write_latest(tmp_path, key=KEY2)
    run(watch.refresh())
    assert watch.blocked_cause == "export_unverified"  # 현재·이전 어느 키도 아니다
    watch.config = cfg(tmp_path, key=KEY, previous=KEY2)
    run(watch.refresh())
    assert watch.blocked_cause is None  # 키 교체 중에는 이전 키로 검증된다


def test_the_first_judgement_failing_starts_blocked_and_later_errors_keep_the_verdict(tmp_path):
    watch = Watch(cfg(tmp_path), FakeDatabase())

    async def broken(sql, params):
        raise OSError("db down")

    watch._row = broken
    run(watch.refresh())
    assert watch.blocked_cause == "export_unverified" and watch.evaluated is False


def test_the_startup_retry_does_not_rejudge_after_the_first_judgement(tmp_path):
    from mint_litellm.plugin.selfcheck import PluginRuntime

    watch = Watch(cfg(tmp_path), FakeDatabase(applied=False))
    runtime = PluginRuntime(config=cfg(tmp_path), database=None, recorder=None, evaluate=None,
                            restore_watch=watch,
                            view_collector=lambda: (_ for _ in ()).throw(RuntimeError))
    run(watch.refresh())
    assert watch.evaluated
    before = len(watch.database.queries)
    try:
        run(runtime.verify())
    except RuntimeError:
        pass  # 점검 항목 수집은 시험 대상이 아니다
    assert len(watch.database.queries) == before  # 30초 재시도가 판정 주기를 앞지르지 않는다


def test_a_database_error_keeps_the_previous_verdict(tmp_path):
    write_latest(tmp_path)
    watch = Watch(cfg(tmp_path), FakeDatabase(facts={"epoch": 5, "has_written": True,
                                                      "has_negative_written": False,
                                                      "missing": 1, "anchor_ok": True}))
    run(watch.refresh())
    run(watch.refresh())
    assert watch.blocked_cause == "restore_pending"

    async def broken(sql, params):
        raise OSError("db down")

    watch._row = broken
    run(watch.refresh())
    assert watch.blocked_cause == "restore_pending"


def test_a_blocked_watch_blocks_every_call_with_the_cause_and_reads_no_file(tmp_path, monkeypatch):
    h = harness(tmp_path)
    state = {"cause": "restore_pending"}
    h.deps.verified = lambda: state["cause"] is None
    h.deps.unverified_cause = lambda: state["cause"]

    def no_files(*args, **kwargs):
        raise AssertionError("핫패스는 파일을 읽지 않는다")

    monkeypatch.setattr(files, "read_verified", no_files)
    monkeypatch.setattr(files, "newest_negative", no_files)
    outcome = decide(h)
    assert code(outcome) == "MINT-ENFORCEMENT-UNVERIFIED"
    assert outcome.snapshot.stop.reason_code == "ENFORCEMENT_UNVERIFIED"
    assert h.snapshots.queries == []
    assert "cause=restore_pending" in outcome.snapshot.stop.detail
    state["cause"] = None
    assert decide(h).allowed


def test_the_runtime_gate_follows_the_watch_in_memory(tmp_path):
    from mint_litellm.plugin.selfcheck import PluginRuntime

    watch = Watch(cfg(tmp_path), FakeDatabase())
    runtime = PluginRuntime(config=cfg(tmp_path), database=None, recorder=None, evaluate=None,
                            restore_watch=watch)
    runtime.verified = True
    assert runtime.deps.verified() is True
    watch.blocked_cause = "export_missing"
    assert runtime.deps.verified() is False and runtime.deps.unverified_cause() == "export_missing"
    runtime_one_stage = PluginRuntime(config=cfg(tmp_path), database=None, recorder=None,
                                      evaluate=None)
    runtime_one_stage.verified = True
    assert runtime_one_stage.deps.verified() is True and (
        runtime_one_stage.deps.unverified_cause() is None)


def test_the_config_reads_the_export_settings(monkeypatch):
    from mint_litellm.plugin.config import PluginConfig

    env = {"MINT_INSTANCE_ID": "i", "MINT_DATABASE_URL": "x", "MINT_OPA_URL": "y"}
    plain = PluginConfig.from_env(env)
    assert plain.export_dir is None and plain.export_hmac_key is None
    with_export = PluginConfig.from_env(
        {**env, "MINT_EXPORT_DIR": "/mnt/export", "MINT_EXPORT_HMAC_KEY": "A" * 43,
         "MINT_EXPORT_HMAC_KEY_PREVIOUS": "B" * 43})
    assert str(with_export.export_dir).endswith("export") and len(with_export.export_hmac_key) == 32
    assert with_export.export_hmac_key_previous is not None
    with pytest.raises(RuntimeError, match="MINT_EXPORT_HMAC_KEY"):
        PluginConfig.from_env({**env, "MINT_EXPORT_HMAC_KEY": "short"})


def test_a_signed_file_with_no_exports_table_blocks_a_restored_stage_one_backup(tmp_path):
    write_latest(tmp_path)
    watch = Watch(cfg(tmp_path), FakeDatabase(applied=False))
    assert run(watch.refresh()) is None
    assert watch.blocked_cause == "export_missing"
    files.latest_path(tmp_path / "export", INSTANCE).unlink()
    run(watch.refresh())
    assert watch.blocked_cause is None  # 서명 파일이 없는 1단계 설치는 그대로 통과


@pytest.mark.parametrize("document", [
    {"key_id": ["x"], "hmac": "00"},
    {"key_id": files.key_id(KEY), "hmac": "00", "value": 1.5},
])
def test_any_exception_while_verifying_a_signature_is_unverified(tmp_path, document):
    path = files.latest_path(tmp_path / "export", INSTANCE)
    path.parent.mkdir(parents=True)
    import json as json_module

    path.write_text(json_module.dumps(document), encoding="utf-8")
    with pytest.raises(files.ExportUnverified):
        files.verify(document, [KEY])
    assert judge.read_files(tmp_path / "export", INSTANCE, [KEY]).error == "unverified"
    watch = Watch(cfg(tmp_path), FakeDatabase())
    run(watch.refresh())
    assert watch.blocked_cause == "export_unverified"
