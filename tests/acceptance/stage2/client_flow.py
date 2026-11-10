"""항목 13에서 실제 두 클라이언트의 다섯 상태를 같은 실행으로 결속한다."""

import base64
import hashlib
import json


def probe(rig, fixture, phase):
    server = fixture["server_id"]
    tool, arguments = next(iter(fixture["changed_tools"].items()))
    for device in ("pj1", "pj3"):
        assert device in rig.site.get("clients", {}), f"실제 클라이언트 연결 없음: {device}"
        payload = {
            "sha": rig.result["sha"], "batch_id": rig.result["batch_id"],
            "device": device, "server": fixture["name"], "phase": phase,
            "tool": fixture.get("client_tool_prefix", "") + tool,
            "arguments": arguments, "counter_url": rig.site["counters"][server],
        }
        before = rig.counter(server)
        if phase in ("active", "reapproved"):
            rig.call_approval(server, tool, arguments)  # 고위험 도구는 호출 1회마다 승인이 필요하다(R2)
        since = rig.sql("SELECT clock_timestamp() AS t")[0]["t"]
        done = rig.command(rig.site["clients"][device], input=json.dumps(payload), timeout=210)
        output = json.loads(done.stdout)
        expected = 1 if phase in ("active", "reapproved") else 0
        assert rig.counter(server) - before == expected
        decisions = rig.sql(
            "SELECT source_key,payload FROM mint.events WHERE instance_id=%s "
            "AND kind='decision_evaluated' AND inserted_at >= %s "
            "AND payload->>'resolved_server_id'=%s", [rig.iid, since, server],
        )
        if expected:
            assert len(decisions) == 1 and decisions[0]["payload"]["enforced_action"] == "allow"
        else:
            assert all(row["payload"]["enforced_action"] == "block" for row in decisions)
        record = output["record"]
        raw = base64.b64decode(output["transcript_base64"], validate=True)
        assert hashlib.sha256(raw).hexdigest() == record["transcript"]["sha256"]
        rig.root.mkdir(parents=True, exist_ok=True)
        target = rig.root / ("client-" + device + ".log")
        target.write_bytes(raw)
        record["transcript"]["path"] = str(target)
        path = rig.root / ("client-" + device + ".json")
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
        rig.site["artifacts"]["client_" + device] = str(path)
        rig.note(device=device, phase=phase, server=fixture["name"], upstream_calls=expected,
                 decision_events=decisions)


def run(rig):
    rig.require("contract reapprove", handlers=("contract_observe", "sync_target"))
    assert rig.site.get("case_setup"), "실제 클라이언트 시험의 초기 상태 복구 명령 없음"
    rig.command([arg.replace("{case}", "client-flow") for arg in rig.site["case_setup"]],
                timeout=180)
    for name in ("playwright", "context7", "grafana"):
        fixture = rig.fixture(name)
        server = fixture["server_id"]
        probe(rig, fixture, "before")
        rig.activate(fixture)
        probe(rig, fixture, "active")
        rig.fault(name + "_upgrade")
        rig.wait(lambda server=server: rig.rows(
            "tool_contracts", "server_id=%s AND drift='input_schema'", [server],
        ), 120, "실제 클라이언트용 드리프트")
        probe(rig, fixture, "drift")
        rig.reapprove(server)
        rig.wait(lambda server=server: not rig.rows(
            "tool_contracts", "server_id=%s AND status='approved' AND drift <> 'none'", [server],
        ), 120, "실제 클라이언트용 재승인")
        probe(rig, fixture, "reapproved")
        for approval in rig.rows("approvals", "server_id=%s AND status='active'", [server]):
            rig.cli("revoke", str(approval["id"]), "--reason", "acceptance")
        probe(rig, fixture, "revoked")
