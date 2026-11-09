"""13. 사건 59종과 핵심 흐름별 원장 건수, 장비 클라이언트 증거 교차 검사."""

import json

from . import client_flow


def test_event_matrix(rig):
    from mint_litellm.types.events import EventKind

    assert set(rig.expected["event_catalog"]) == {kind.value for kind in EventKind}
    assert len(rig.expected["event_catalog"]) == 59
    required = set(rig.expected["required_flows"])
    found = set()
    records = []
    for path in rig.root.glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if (record.get("status") != "passed" or record.get("sha") != rig.result["sha"]
                or record.get("batch_id") != rig.result["batch_id"]):
            continue
        records.append(record)
        for step in record["steps"]:
            if "expected_events" in step:
                actual = step["actual_events"]
                assert all(actual.get(kind, 0) == count
                           for kind, count in step["expected_events"].items())
                found.add(step["flow"])
    for filename, count in rig.expected["required_scripts"].items():
        matching = [record for record in records if filename in record["test"]]
        assert len(matching) == count, f"필수 시험 누락: {filename} {len(matching)}/{count}"
    assert required <= found, f"같은 SHA의 합격 증거 누락: {sorted(required - found)}"
    client_flow.run(rig)
    # REST 대체 호출은 pj1·pj3의 Claude Code 증거가 아니다.
    for name in ("pj1", "pj3"):
        record = rig.read_observation("client_" + name)
        assert record["client"] == "claude-code" and record["device"] == name
        assert record["sha"] == rig.result["sha"]
        for server in ("playwright", "context7", "grafana"):
            rig.check_observation("client_flow", record["servers"][server])
        rig.verify_artifact(record["transcript"])
    rig.note(flow_matrix=sorted(found), prior_results=len(records), catalog_count=59)
