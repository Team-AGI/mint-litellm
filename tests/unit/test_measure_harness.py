import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEASURE = ROOT / "scripts" / "measure"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"measure_{name}", MEASURE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("runner")
score = _load("score")


def test_wilson_zero_errors_has_rule_of_three_bound():
    low, high = score.wilson(0, 100)
    assert low == 0.0
    assert 0.03 < high < 0.045
    assert score.required_n(0, 0.01) == 300


def test_wilson_known_value():
    low, high = score.wilson(50, 100)
    assert abs(low - 0.4038) < 1e-3 and abs(high - 0.5962) < 1e-3


def test_plan_interleaves_every_config_each_run_and_is_seeded():
    ids = ["a", "b", "c"]
    slots = runner.plan(ids, 20, seed=7)
    assert slots == runner.plan(ids, 20, seed=7)
    for run in range(20):
        assert sorted(s["config"] for s in slots if s["run"] == run) == ids
    orders = {tuple(s["config"] for s in slots if s["run"] == r) for r in range(20)}
    assert len(orders) > 1
    assert {s["config"] for s in slots if s["position"] == 0} == set(ids)


def test_server_timing_parse():
    assert runner.parse_server_timing("pre;dur=1.5, upstream;dur=30") == {
        "pre": 1.5,
        "upstream": 30.0,
    }
    assert runner.parse_server_timing(None) == {}


def test_run_slot_marks_cold_then_warm_and_keeps_failures():
    cfg = {"status_to_action": {"200": "allow", "403": "deny"}}
    cases = [{"id": "x"}, {"id": "y"}]
    replies = iter([200, 403, 500])

    def send(_c, _case, _t):
        status = next(replies)
        if status == 500:
            raise OSError
        return status, {"pre": 1.0}

    rows = list(runner.run_slot(cfg, cases, {"run": 0, "position": 0, "config": "k"}, 1, 2, send))
    assert [r["phase"] for r in rows] == ["cold", "warm", "warm"]
    assert [r["action"] for r in rows] == ["allow", "deny", "error"]
    assert rows[2]["error"] == "OSError"


def test_paired_difference_uses_allowed_warm_calls_only():
    rec = []
    for run in range(5):
        for cfg, base in (("p", 10), ("m", 14)):
            for i in range(20):
                rec.append(
                    {
                        "run": run,
                        "config": cfg,
                        "phase": "warm",
                        "action": "allow",
                        "total_ms": base + i * 0.1,
                    }
                )
            rec.append(
                {"run": run, "config": cfg, "phase": "warm", "action": "deny", "total_ms": 1.0}
            )
    out = runner.paired_difference(rec, "p", "m", 0.5)
    assert out["runs"] == 5 and abs(out["mean"] - 4.0) < 1e-9
    assert out["ci95"][0] <= 4.0 <= out["ci95"][1]


def test_ready_check_refuses_unfilled_parity():
    base = json.loads((MEASURE / "configs/baseline.json").read_text(encoding="utf-8"))
    try:
        runner.check_ready(base, [])
    except SystemExit:
        return
    raise AssertionError("빈 자원 동등 값을 거부해야 한다")


def test_scorer_confusion_and_evaluated_vs_enforced():
    corpus = score.load(MEASURE / "corpus/seed.jsonl")
    assert {c["source"] for c in corpus} == {"synthetic"}
    observed = [{"id": c["id"], "evaluated": c["expect"], "enforced": c["expect"]} for c in corpus]
    for o in observed:
        if o["id"] == "s14":
            o["enforced"] = "deny"
    ev = score.score(corpus, observed, "evaluated")
    en = score.score(corpus, observed, "enforced")
    assert ev["labels"]["observe"]["correct"] == 1 and ev["unseen"] == 0
    assert en["labels"]["observe"]["correct"] == 0
    assert en["labels"]["observe"]["confusion"] == {"deny": 1}
    assert en["labels"]["allow"]["precision"] == 1.0


def test_scorer_split_and_missing_not_hidden():
    corpus = score.load(MEASURE / "corpus/seed.jsonl")
    res = score.score(corpus, [], "evaluated", "tune")
    assert res["unseen"] == sum(c["split"] == "tune" for c in corpus)
