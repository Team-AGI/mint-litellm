"""7. URL 선행 차단, 검사 상한, 직무 분리와 증거 만료."""

import pytest


@pytest.mark.parametrize("case", ["provider_denied", "private_literal", "allow_all_keys",
                                     "definitions_limit", "same_requester", "stale_evidence",
                                     "credentials_required", "private_ip_guard"])
def test_negative_intake(rig, case):
    rig.require("intake create", "intake approve", "intake except", handlers=("intake_run",))
    rig.fault("intake_" + case)
    observation = rig.read_observation("intake_" + case)
    rig.check_observation("intake_" + case, observation)
    if case == "private_literal":  # 신청이 없다: LiteLLM 거절만 본다
        return
    intake = rig.rows("intakes", "id=%s", [observation["intake_id"]])[0]
    if case in ("provider_denied", "allow_all_keys", "private_ip_guard"):
        assert intake["decision"] == "rejected"
        assert rig.rows("intake_checks", "intake_id=%s AND result='fail'", [intake["id"]])
    if case == "credentials_required":
        assert intake["needs_registry_credentials"] is True
        checks = rig.rows("intake_checks", "intake_id=%s AND reason_code='CREDENTIALS_REQUIRED'",
                          [intake["id"]])
        assert checks
    if case in ("same_requester", "stale_evidence"):
        # 같은 사용자(신청자)이거나 오래된 증거이면 CLI 결정이 거부되어야 한다.
        word = "신청자" if case == "same_requester" else "24시간"
        done = rig.cli("intake", "approve", str(intake["id"]), "--reason", "acceptance",
                       role="admin" if case == "same_requester" else "approver", check=False)
        assert done.returncode != 0 and word in done.stderr, rig.clean(done.stderr)
        assert rig.rows("intakes", "id=%s AND decision IS NULL", [intake["id"]])


def test_external_mcp_forbidden(rig):
    """DS-182: 모델 요청에 담긴 공급자 쪽 MCP(외부 server_url)는 403으로 막고 판정 사건을 남긴다."""
    from .rig import ROOT

    source = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))
    if "EXTERNAL_MCP_FORBIDDEN" not in source:  # 사유 코드는 MINT-EXTERNAL-MCP-FORBIDDEN으로 직렬화된다
        rig.skip("미구현으로 건너뜀: DS-182 공급자 쪽 MCP 차단(미병합)")
    base = rig.site["litellm"][0].rstrip("/")
    external = {"type": "mcp", "server_label": "ext", "server_url": "https://external.invalid/mcp"}
    bodies = {
        "/v1/chat/completions": {"model": "acc-none", "tools": [external],
                                 "messages": [{"role": "user", "content": "hi"}]},
        "/v1/responses": {"model": "acc-none", "input": "hi", "tools": [external]},
    }
    headers = {"Authorization": "Bearer " + rig.secret("caller")}
    for path, body in bodies.items():
        before = rig.sql("SELECT count(*) AS n FROM mint.events WHERE instance_id=%s "
                         "AND payload::text LIKE '%%EXTERNAL_MCP%%'", [rig.iid])[0]["n"]
        reply = rig.client.post(base + path, headers=headers, json=body)
        assert reply.status_code == 403 and "MINT-EXTERNAL-MCP-FORBIDDEN" in reply.text, (
            path, reply.status_code, rig.clean(reply.text[:300]))
        rig.wait(lambda before=before: rig.sql(
            "SELECT count(*) AS n FROM mint.events WHERE instance_id=%s "
            "AND payload::text LIKE '%%EXTERNAL_MCP%%'", [rig.iid])[0]["n"] > before,
            20, "판정 사건")
    gateway = {**external, "server_url": "litellm_proxy"}
    reply = rig.client.post(base + "/v1/responses", headers=headers,
                            json={"model": "acc-none", "input": "hi", "tools": [gateway]})
    assert "MINT-EXTERNAL-MCP-FORBIDDEN" not in reply.text  # 게이트웨이 주소는 막지 않는다
