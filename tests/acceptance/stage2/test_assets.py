"""DB 없는 자산 자체 검사. 제품 동작을 대신하는 시험은 아니다."""

import ast

import pytest

from .latency import arguments, extract, quantiles
from .rig import HERE, ROOT, load_expectations


def test_catalog_matches_source_without_loading_product():
    tree = ast.parse((ROOT / "src/mint_litellm/types/events.py").read_text(encoding="utf-8"))
    enum = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                and node.name == "EventKind")
    kinds = {node.value.value for node in enum.body if isinstance(node, ast.Assign)
             and isinstance(node.value, ast.Constant)}
    expected = load_expectations()
    assert len(kinds) == len(expected["event_catalog"]) == 59
    assert kinds == set(expected["event_catalog"])
    for counts in expected["flows"].values():
        assert set(counts) <= kinds
        assert all(isinstance(value, (int, str)) for value in counts.values())


def test_latency_boundaries_and_sample_selection():
    import json

    assert len(json.dumps(arguments("64kb"), separators=(",", ":")).encode()) == 65536
    assert quantiles(list(range(1, 101))) == {"p50": 50, "p95": 95, "p99": 99}
    raw = "decision_ms=999 ref=warmup allowed=true\ndecision_ms=23 ref=sample allowed=true"
    assert extract(raw, {"sample"}) == [23]
    with pytest.raises(AssertionError, match="누락"):
        extract(raw, {"absent"})
    with pytest.raises(AssertionError, match="중복"):
        extract(raw + "\ndecision_ms=24 ref=sample allowed=true", {"sample"})


def test_thirteen_scripts_and_text_encoding():
    for index in range(1, 14):
        assert len(list(HERE.glob(f"test_{index:02d}_*.py"))) == 1
    for path in HERE.rglob("*"):
        if path.suffix in {".py", ".yaml", ".md", ".json"} and not set(
            path.relative_to(HERE).parts
        ) & {"evidence", ".runtime", "__pycache__"}:
            raw = path.read_bytes()
            assert not raw.startswith(b"\xef\xbb\xbf"), path
            assert b"\r" not in raw, path
            assert "\ufffd" not in raw.decode("utf-8"), path


def test_observation_contracts_cover_cases():
    expected = load_expectations()
    prefixes = {
        "test_04_sync.py": "sync_",
        "test_06_restore.py": "restore_",
        "test_07_intake_negative.py": "intake_",
        "test_08_confirmation.py": "confirmation_",
        "test_09_auth_ui.py": "auth_",
    }
    for filename, prefix in prefixes.items():
        tree = ast.parse((HERE / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and (
                node.func.attr == "parametrize" and node.args[0].value == "case"
            ):
                for name in ast.literal_eval(node.args[1]):
                    assert prefix + name in expected["observations"], (filename, name)


def test_every_required_fault_has_a_named_adapter():
    from .adapters import ADAPTERS, SKIPPED, emit_site, main
    from .inventory import required_faults

    site = emit_site(repo="/clone")
    assert set(required_faults()) <= set(site["faults"]) == set(ADAPTERS) - {
        "db_backup", "db_restore", "snapshot"}
    assert all(f["apply"][0] == "bash" and "{observation}" in " ".join(f["apply"])
               for f in site["faults"].values())
    assert main(["no_such", "apply"]) == 2
    # 46종 모두 본문이 있고, 직원 화면(G8b) 의존 사례만 건너뜀으로 끝난다
    from .adapters import SCENARIOS
    from .scenarios import BODIES
    assert len(BODIES) == 47 and set(BODIES) <= set(SCENARIOS)
    assert not [n for n in SCENARIOS if getattr(ADAPTERS[n][0], "pending", False)]
    assert main(["auth_screens_13", "apply"]) == SKIPPED


def test_generated_commands_replace_shell_placeholders():
    import shlex

    from .adapters import emit_site
    from .rig import Rig

    site = emit_site(ssh="test-host", repo="/test repo")
    command = site["faults"]["auth_plugin_control_event"]["apply"]
    replaced = Rig.replace_placeholders(command, {
        "{observation}": "/test evidence/a'b.json", "{run_id}": "run-1",
    })
    assert replaced[:2] == ["ssh", "test-host"]
    assert "{observation}" not in replaced[2] and "{run_id}" not in replaced[2]
    assert shlex.quote("/test evidence/a'b.json") in replaced[2]
    setup = Rig.replace_placeholders(site["case_setup"], {"{case}": "test[a b]"})
    assert shlex.quote("test[a b]") in setup[2]
