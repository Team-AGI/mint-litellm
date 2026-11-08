"""2. 공개 서버 판본 변경, 합성 서버의 설명·도구 추가·삭제·배포 변경."""

import os

import pytest


@pytest.mark.parametrize("name", ["playwright", "context7", "grafana"])
def test_version_drift_and_reapproval(rig, name):
    rig.require("contract reapprove", handlers=("contract_observe", "sync_server"))
    fixture = rig.active(name)
    server = fixture["server_id"]
    rig.fault(name + "_upgrade")
    rig.wait(lambda: rig.rows("tool_contracts", "server_id=%s AND drift='input_schema'", [server]),
             240, "입력 스키마 관측")
    for tool, args in fixture["changed_tools"].items():
        rig.call(server, tool, args, allowed=False, code="MINT-CONTRACT-DRIFT-input-schema")
    rig.call(server, fixture["unchanged_tool"], fixture["unchanged_arguments"])
    contracts = rig.rows("tool_contracts", "server_id=%s AND drift='input_schema'", [server])
    if not os.environ.get("ACC_DS183"):
        # DS-183(드리프트 뒤 후보 계약 자동 생성)이 병합되면 ACC_DS183=1로 켠다. 흐름: 후보 자동 생성
        # (재검사 작업) → 재승인 → 재pin → 허용. 그 전에는 후보가 없어 재승인을 시험할 수 없다.
        rig.skip("제품 수정 대기: DS-183 후보 자동 생성(재승인 단계)")
    window = rig.begin("reapproval", entities=[row["id"] for row in contracts], server=server)
    rig.reapprove(server)
    changed = rig.reapproved_tools
    rig.wait(lambda: not rig.rows("tool_contracts", "server_id=%s AND status='approved' "
                                "AND drift <> 'none'", [server]), 120, "재승인·재pin")
    for tool, args in fixture["changed_tools"].items():
        rig.call(server, tool, args, app_error_ok=True)
    rig.check_events(window, changed_count=changed)


@pytest.mark.parametrize("mutation", ["description", "added", "removed", "deployment"])
def test_synthetic_contract_changes(rig, mutation):
    rig.require("contract reapprove", handlers=("contract_observe",))
    fixture = rig.active("synthetic")
    server = fixture["server_id"]
    window = rig.begin("drift_" + mutation, server=server)
    rig.fault("contract_" + mutation)
    if mutation == "description":
        rig.wait(lambda: rig.rows("tool_contracts", "server_id=%s AND drift='description'",
                                  [server]), 240, "설명 변경")
        rig.call(server, fixture["tool"], fixture["arguments"])
    elif mutation == "added":
        # 추가 도구는 후보 행이 아니라 관측 사건·경보로 드러나고 호출은 unapproved_tool로 막힌다.
        rig.wait(lambda: rig.sql(
            "SELECT 1 FROM mint.events WHERE instance_id=%s AND kind='contract_drift_detected' "
            "AND inserted_at >= %s AND payload->>'server_id'=%s",
            [rig.iid, window["since"], server]), 240, "추가 도구 관측")
        # LiteLLM의 도구 목록에 없는 도구라 사전 거절도 합격이다(업스트림 0, DS-173). MINT 판정이 있으면 코드도 본다.
        rig.call(server, fixture["added_tool"], {}, allowed=False, litellm_rejects=True,
                 code="MINT-CONTRACT-DRIFT-unapproved-tool")
    elif mutation == "removed":
        rig.wait(lambda: rig.rows("tool_contracts", "server_id=%s AND tool=%s "
                                  "AND status='superseded'", [server, fixture["tool"]]),
                 240, "삭제 계약 폐기")
    else:
        # 호출을 보내지 않은 채 두 복제본이 각각 불일치를 관측해야 한다.
        rig.wait(lambda: rig.rows("servers", "server_id=%s AND deployment_drift", [server]),
                 240, "배포 변경")
        rig.wait(lambda: rig.rows("alerts", "kind='contract_drift' AND subject->>'server_id'=%s",
                                  [server]), 120, "배포 변경 경보")
        rig.check_events(window, worker_count=2)
        # DS-185 ①: 제한된 제어 키는 새 URL을 돌려주지 않으므로 운영자가 등록된 새 주소를 입력해 후보를 만든다.
        url = rig.request("GET", f"/v1/mcp/server/{server}", role="litellm_admin",
                          base="litellm_admin")["url"]
        intake = max(rig.rows("intakes", "server_id=%s AND decision='approved'", [server]),
                     key=lambda row: row["decided_at"])
        rig.cli("intake", "recheck", str(intake["id"]), "--url", url, role="admin")
        rig.reapprove(server, need_deployment=True)
        try:
            rig.wait(lambda: not rig.rows("servers", "server_id=%s AND deployment_drift", [server]),
                     120, "배포 재승인")
        except AssertionError:
            dep = rig.sql("SELECT status, count(*) AS n FROM mint.deployment_contracts WHERE "
                          "instance_id=%s AND server_id=%s GROUP BY 1", [rig.iid, server])
            ev = rig.sql("SELECT kind, count(*) AS n FROM mint.events WHERE instance_id=%s AND "
                         "inserted_at >= %s GROUP BY 1", [rig.iid, window["since"]])
            raise AssertionError(f"deployment_contracts={dep} events={ev}")
        rig.call(server, fixture["tool"], fixture["arguments"])
        return
    rig.check_events(window)
