"""원격 승인 서버가 PC 목록에 보이고, 폐기된 서버는 계약 파일에서 정리된다."""

import json
import re
from types import SimpleNamespace

import pytest
from test_kit_install import CONTRACT, kit_module, make_kit, unpack
from test_kit_refresh import item
from test_kit_remediation import stage_report

REMOTE = "ms_learn"
NEXT = "하네스의 게이트웨이 연결(litellm_gateway)로 씁니다"


class Gate:
    def __init__(self, me):
        self.me = me

    def json(self, method, path, body=None):
        return 200, self.me


def installed(tmp_path, managed):
    kit = make_kit(unpack(tmp_path, harnesses=("claude",)), tmp_path, managed=managed)
    return kit, kit.install()


def contracts(kit):
    return json.loads((kit.programs / "contracts.json").read_text())["servers"]


def retire(kit, *names):
    path = kit.home / ".cache/mint/retired.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"servers": list(names), "at": 1.0}))


# -- QA-BUG-102: 원격 승인 -----------------------------------------------------------------------


def test_an_approved_remote_server_is_listed_shown_and_never_downloaded(tmp_path, reports, capsys):
    kit, state = installed(tmp_path, True)
    gate = Gate({"user": "u", "servers": [], "remote_servers": [REMOTE, REMOTE], "intakes": []})
    args = SimpleNamespace(json=True, fields=None, server=REMOTE)
    assert kit_module.run_server_list(args, kit, state, gate) == 0
    rows = json.loads(capsys.readouterr().out)["servers"]
    assert [(r["server_id"], r["kind"], r["state"], r["next"]) for r in rows
            if r["kind"] == "원격"] == [(REMOTE, "원격", "사용 가능", NEXT)]
    assert kit_module.run_server_show(args, kit, state, gate) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "원격"
    assert kit_module.run_server_get(args, kit, gate) == 0  # 안내만 한다
    assert "받을 것이 없습니다" in capsys.readouterr().out


def test_remote_rows_sit_after_local_ones_and_a_missing_field_changes_nothing(tmp_path, reports):
    kit, state = installed(tmp_path, True)
    kit.refresh(state, [item("srv-9", CONTRACT)])
    me = {"user": "u", "servers": [{"server_id": "srv-9"}], "remote_servers": [REMOTE]}
    names = [r["name"] for r in kit_module.build_model(kit, state, Gate(me))["servers"]]
    assert names[-2:] == ["srv-9", REMOTE] and names.count(REMOTE) == 1
    old = kit_module.build_model(kit, state, Gate({"user": "u", "servers": []}))["servers"]
    assert REMOTE not in [r["name"] for r in old]  # 옛 게이트웨이 응답에는 원격 목록이 없다


def test_the_terminal_tab_shows_the_remote_server(tmp_path, reports):
    kit, state = installed(tmp_path, True)
    model = kit_module.build_model(kit, state, Gate({"user": "u", "remote_servers": [REMOTE]}))
    ui = {"tab": 1, "cursor": len(model["servers"]) - 1, "detail": True, "message": ""}
    text = "\n".join(kit_module.render_screen(model, ui, 100, 30, False))
    assert REMOTE in text and "원격" in text and "사용 가능" in text and NEXT in text


# -- QA-BUG-105: 폐기 서버의 계약 정리 ------------------------------------------------------------


@pytest.mark.parametrize("managed", [True, False])
def test_retired_servers_leave_the_contract_file_and_other_entries_stay(tmp_path, reports, managed):
    kit, state = installed(tmp_path, managed)
    kit.refresh(state, [item("srv-1", CONTRACT), item("srv-2", CONTRACT)])
    assert {"srv-1", "srv-2"} <= set(contracts(kit))
    assert kit.drop_contracts(state, ["srv-1", "ghost"]) == ["srv-1"]
    assert "srv-1" not in contracts(kit) and "srv-2" in contracts(kit)
    assert kit.drop_contracts(state, ["srv-1"]) == []  # 두 번째는 할 일이 없다


def test_a_contract_file_the_kit_did_not_write_is_left_alone(tmp_path, reports):
    kit, state = installed(tmp_path, False)
    kit.refresh(state, [item("srv-1", CONTRACT)])
    path = kit.programs / "contracts.json"
    doc = json.loads(path.read_text())
    doc["servers"]["mine"] = doc["servers"]["srv-1"]
    path.write_text(json.dumps(doc))  # 사용자가 손댄 파일은 기록한 해시와 다르다
    assert kit.drop_contracts(state, ["srv-1"]) == []
    assert "srv-1" in contracts(kit)


def test_the_report_runner_drops_retired_contracts_in_both_modes(tmp_path, monkeypatch):
    for mode in ("managed", "user"):
        (tmp_path / mode).mkdir()
        seen = []
        monkeypatch.setattr(kit_module.Kit, "drop_contracts",
                            lambda self, st, names, seen=seen: seen.append(names) or [])
        programs, home, _ = stage_report(
            tmp_path / mode, monkeypatch, mode, {"recorded": True, "retired": ["srv-1"]})
        monkeypatch.setattr(kit_module.Kit, "remediate", lambda self, st, names: [])
        code = kit_module.report_installed(
            programs, home=home, user="tester", sleep=lambda s: None, now=lambda: 1.0)
        assert code == 0 and seen == [["srv-1"]], mode


def test_a_retired_server_that_still_has_a_contract_reads_as_ended(tmp_path, reports, capsys):
    kit, state = installed(tmp_path, True)
    kit.refresh(state, [item("srv-1", CONTRACT)])
    retire(kit, "srv-1")
    gate = Gate({"user": "u", "servers": [], "intakes": []})
    model = kit_module.build_model(kit, state, gate)
    row = next(r for r in kit_module.server_rows(model) if r["server_id"] == "srv-1")
    assert row["state"] == "이용 종료" and "mint report" not in row["next"]
    assert not re.search("준비 중|만료", json.dumps(row, ensure_ascii=False))
