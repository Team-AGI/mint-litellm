"""결함 B(DS-190) 재확인: LiteLLM·작업 실행기 재시작 직후에도 승인된 도구가 목록에 남는다.

`docker restart`로 두 컨테이너를 다시 띄우고, LiteLLM이 준비된 뒤 관측 주기 세 번 동안 5초마다
호출 키로 `tools/list`를 본다. 미관측 차단(2×관측 주기)에 닿으면 목록이 비므로 빈 목록이 한 번도
없어야 한다. 13항목 필수 건수(`required_scripts`)에는 넣지 않는다.
"""

import os
import time

import httpx


def test_restart_gap(rig):
    rig.require("contract show", handlers=("contract_observe",))
    fixture = rig.active("synthetic")
    server = fixture["server_id"]
    base = rig.site["litellm"][0].rstrip("/")
    observe = rig.expected["limits"]["observe_seconds"]
    containers = os.environ.get("ACC_RESTART_CONTAINERS",
                                "mints2-litellm-1 mints2-worker-1").split()

    def listed():
        try:
            response = rig.client.get(base + "/mcp-rest/tools/list", params={"server_id": server},
                                      headers={"Authorization": "Bearer " + rig.secret("caller")},
                                      timeout=10)
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        return len(response.json().get("tools", []))

    assert listed(), "재시작 전 목록이 이미 비어 있음"
    rig.command(["docker", "restart", *containers], timeout=180)
    restarted = time.monotonic()
    rig.wait(lambda: listed() is not None, 300, "재시작 뒤 LiteLLM 준비")
    ready = time.monotonic() - restarted
    samples = []
    while time.monotonic() - restarted < ready + 3 * observe:
        samples.append(listed())
        time.sleep(5)
    jobs = rig.rows("jobs", "kind='contract_observe' AND updated_at > clock_timestamp() - "
                            "interval '10 minutes'")
    rig.note(ready_seconds=ready, samples=len(samples), empty=samples.count(0),
             unavailable=samples.count(None), observe_seconds=observe,
             observe_jobs=[{"status": j["status"], "attempts": j["attempts"],
                            "last_error_code": j.get("last_error_code")} for j in jobs])
    assert samples.count(0) == 0, f"재시작 뒤 빈 목록 {samples.count(0)}/{len(samples)}"
    rig.call(server, fixture["tool"], fixture["arguments"])
