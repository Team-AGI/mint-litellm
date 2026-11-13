"""승인 서버 목록 반영: 관리형은 자기 항목만 고치고, 사용자 수준은 파일을 고치지 않는다."""

import json
import os
import tomllib

import pytest
from test_kit_install import CONTRACT, kit_module, make_kit, unpack

from mint_litellm.endpoint.refresh import contract_version, desired_servers

BOTH = ("claude", "codex")
NEW = {**CONTRACT, "executable": "/usr/bin/python3", "argv": ["/opt/new/server.py"]}
CHANGED = {**CONTRACT, "argv": ["/opt/srv/index2.js"]}
PLAIN = {k: v for k, v in CONTRACT.items() if k != "identity_kind"}


def item(name, contract):
    contract = {k: v for k, v in contract.items() if k != "identity_kind"}
    return {"name": name, "version": contract_version(contract), "contract": contract}


def installed(tmp_path, *, managed=True, harnesses=("claude",), **options):
    folder = unpack(tmp_path, harnesses=harnesses)
    kit = make_kit(folder, tmp_path, managed=managed, **options)
    return kit, kit.install()


def listed(kit):
    return json.loads((kit.managed_dir / "managed-mcp.json").read_text())["mcpServers"]


def contracts(kit):
    return json.loads((kit.programs / "contracts.json").read_text())["servers"]


def test_the_version_is_the_same_on_both_sides():
    assert kit_module.contract_version(PLAIN) == contract_version(PLAIN)


def test_the_desired_list_has_one_checked_item_per_approved_server():
    items = desired_servers({"b": CONTRACT, "a": NEW})
    assert [i["name"] for i in items] == ["a", "b"]
    assert items[1]["contract"] == PLAIN and items[1]["version"] == contract_version(PLAIN)
    assert "identity_kind" not in items[0]["contract"]


def test_a_new_approval_is_added_and_a_changed_contract_is_updated(tmp_path, reports):
    kit, state = installed(tmp_path)
    desired = [item("srv-1", CONTRACT), item("srv-2", CHANGED), item("srv-3", NEW)]
    assert kit.refresh(state, desired) == ["srv-2", "srv-3"]
    assert sorted(listed(kit)) == ["srv-1", "srv-2", "srv-3"]
    assert listed(kit)["srv-3"]["args"][-2:] == ["--server", "srv-3"]
    assert listed(kit)["srv-3"]["command"] == state["python"]
    assert contracts(kit)["srv-2"]["argv"] == ["/opt/srv/index2.js"]
    assert contracts(kit)["srv-3"]["executable"] == "/usr/bin/python3"
    saved = json.loads((kit.programs / "state.json").read_text())
    assert saved["mcp_servers"] == ["srv-1", "srv-2", "srv-3"]
    # 같은 목록을 다시 받으면 할 일이 없다.
    assert kit.refresh(state, desired) == []
    # 갱신한 파일도 우리 것으로 기록되어 제거하면 아무것도 남지 않는다.
    assert kit.uninstall()["kept"] == []


def test_user_entries_are_never_touched_and_a_same_named_one_is_skipped(tmp_path, reports):
    kit, state = installed(tmp_path)
    path = kit.managed_dir / "managed-mcp.json"
    data = json.loads(path.read_text())
    data["mcpServers"]["user-own"] = {"command": "node", "args": ["/opt/own/index.js"]}
    mine = {"command": "node", "args": ["/opt/mine.js"]}
    data["mcpServers"]["srv-3"] = mine  # 사용자가 같은 이름으로 만든 항목
    path.write_text(json.dumps(data))
    assert kit.refresh(state, [item("srv-3", NEW), item("srv-4", NEW)]) == ["srv-4"]
    after = listed(kit)
    assert after["srv-3"] == mine and after["user-own"] == data["mcpServers"]["user-own"]
    assert "srv-4" in after
    assert "srv-3" not in json.loads((kit.programs / "state.json").read_text())["mcp_servers"]


def test_items_with_a_wrong_version_or_shape_are_dropped(tmp_path, reports):
    kit, state = installed(tmp_path)
    bad = [
        {**item("srv-3", NEW), "version": "0" * 64},
        {**item("../x", NEW)},
        {"name": "srv-5", "version": "v", "contract": {"argv": []}},
        "text",
        {**item("srv-6", NEW), "contract": "x"},
    ]
    assert kit.refresh(state, bad) == []
    assert sorted(listed(kit)) == ["srv-1", "srv-2"]


def test_a_retired_server_is_not_brought_back(tmp_path, reports):
    kit, state = installed(tmp_path)
    assert kit.refresh(state, [item("srv-3", NEW)], retired=["srv-3"]) == []
    assert "srv-3" not in listed(kit)


def test_an_approval_that_returns_after_the_cleanup_is_added_again(tmp_path, reports):
    kit, state = installed(tmp_path)
    kit.remediate(state, ["srv-1"])
    assert "srv-1" not in listed(kit)
    assert kit.refresh(state, [item("srv-1", CONTRACT)]) == ["srv-1"]
    assert "srv-1" in listed(kit)


def test_a_contract_file_someone_else_changed_is_left_alone(tmp_path, reports, capsys):
    kit, state = installed(tmp_path)
    path = kit.programs / "contracts.json"
    path.write_text(path.read_text() + "\n")
    before = path.read_bytes()
    assert kit.refresh(state, [item("srv-3", NEW)]) == []
    assert path.read_bytes() == before and "srv-3" not in listed(kit)
    assert "계약 파일" in capsys.readouterr().err


def test_a_user_level_install_only_says_what_changed(tmp_path, reports, capsys):
    kit, state = installed(tmp_path, managed=False)
    settings = (kit.home / ".claude/settings.json").read_bytes()
    before = (kit.programs / "contracts.json").read_bytes()
    assert kit.refresh(state, [item("srv-1", CONTRACT), item("srv-3", NEW)]) == []
    assert "srv-3" in capsys.readouterr().err
    assert (kit.programs / "contracts.json").read_bytes() == before
    assert (kit.home / ".claude/settings.json").read_bytes() == settings


def test_codex_tables_are_added_in_both_files_and_stay_valid(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("codex",))
    codex = kit.codex_managed_dir
    path = codex / "managed_config.toml"
    path.write_text(path.read_text() + '\n[mcp_servers."srv-4"]\ncommand = "mine"\n')
    desired = [item("srv-3", NEW), item("srv-4", NEW), item("srv-1", CHANGED)]
    assert kit.refresh(state, desired) == ["srv-1", "srv-3"]
    tables = tomllib.loads(path.read_text())["mcp_servers"]
    assert sorted(tables) == ["srv-1", "srv-2", "srv-3", "srv-4"]
    assert tables["srv-4"] == {"command": "mine"}  # 사용자가 쓴 표는 그대로다.
    assert tables["srv-3"]["args"][-2:] == ["--server", "srv-3"]
    requirements = tomllib.loads((codex / "requirements.toml").read_text())
    assert sorted(requirements["mcp_servers"]) == ["srv-1", "srv-2", "srv-3"]
    assert "hooks" in requirements and requirements["allow_managed_hooks_only"] is True
    # 사용자가 표를 더한 파일은 제거할 때도 사용자의 것으로 남는다.
    assert kit.uninstall()["kept"] == [f"{kit.codex_dir}/managed_config.toml"]


def test_a_windows_managed_kit_adds_to_the_block_but_a_system_run_does_not(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=BOTH)
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    config = tmp_path / "home/.codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers."mine"]\ncommand = "x"\n', encoding="utf-8")
    state = kit.install()
    kit.system_mode = True
    kit.refresh(state, [item("srv-3", NEW)])
    assert "srv-3" in listed(kit)  # 관리형 파일은 SYSTEM도 고친다.
    assert "srv-3" not in tomllib.loads(config.read_text(encoding="utf-8"))["mcp_servers"]
    kit.system_mode = False
    state["mcp_servers"].remove("srv-3")
    kit.refresh(state, [item("srv-3", NEW), item("srv-5", NEW)])
    tables = tomllib.loads(config.read_text(encoding="utf-8"))["mcp_servers"]
    assert sorted(tables) == ["mine", "srv-1", "srv-2", "srv-3", "srv-5"]
    assert tables["mine"] == {"command": "x"}
    assert state["codex_config_sha"] == kit_module.sha256_bytes(config.read_bytes())


def stage(tmp_path, monkeypatch, post):
    kit, _ = installed(tmp_path)
    monkeypatch.setenv("HOME", str(kit.home))
    monkeypatch.setenv("USERPROFILE", str(kit.home))
    key = kit.home / ".config/mint/key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("sk-user\n")
    monkeypatch.setattr(kit_module, "post", post)
    monkeypatch.setattr(kit_module, "windows_system", lambda: False)
    return kit


def test_the_periodic_report_applies_the_answer_and_reports_the_result(
    tmp_path, monkeypatch, reports
):
    sent, calls = [], []
    answers = [{"recorded": True, "desired": [item("srv-3", NEW)], "retired": ["old"]},
               {"recorded": True}]

    def post(url, key, payload, ca_file):
        sent.append(payload)
        return answers[len(sent) - 1]

    def refresh(self, state, desired, retired=None):
        calls.append((desired, retired))
        return ["srv-3"]

    kit = stage(tmp_path, monkeypatch, post)
    monkeypatch.setattr(kit_module.Kit, "refresh", refresh)
    code = kit_module.report_installed(
        kit.programs, home=kit.home, sleep=lambda s: None, now=lambda: 1.0
    )
    assert code == 0 and len(sent) == 2  # 바뀐 것이 있으면 곧바로 다시 보고한다.
    assert calls == [([item("srv-3", NEW)], ["old"])]


@pytest.mark.parametrize("desired", [None, "x", {"name": "a"}])
def test_an_answer_without_a_usable_list_changes_nothing(tmp_path, monkeypatch, reports, desired):
    answer = {"recorded": True} | ({} if desired is None else {"desired": desired})
    sent = []
    kit = stage(tmp_path, monkeypatch, lambda *args: sent.append(args) or answer)
    assert kit_module.report_installed(kit.programs, home=kit.home, sleep=lambda s: None) == 0
    assert len(sent) == 1


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root")
def test_a_contract_file_owned_by_someone_else_is_not_trusted_by_a_root_run(tmp_path, reports):
    kit, state = installed(tmp_path)
    kit.root_owned = lambda: True  # 실제 시스템에서 root로 돌 때와 같은 점검
    path = kit.programs / "contracts.json"
    assert kit.refresh(state, [item("srv-3", NEW)]) == ["srv-3"]  # root 소유 파일은 받아들인다.
    os.chown(path, 1234, 1234)
    assert kit.refresh(state, [item("srv-4", NEW)]) == []
    assert "srv-4" not in listed(kit)
