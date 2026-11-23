"""운영 자기 점검: 작업 ``operational_check``(기동 직후와 5분마다).

LiteLLM 연결, 제어 키 유효, 가드레일 중복 등록 없음, 내보내기 디스크 여유를 본다. 문제가 있으면
점검 이름별 경보 한 줄을 올리고(같은 문제는 횟수만 올린다), 풀리면 스스로 닫는다. 작업 실행기에는
마스터 키가 없으므로 키 재발급은 ``mint.sh up``이 맡고, 경보 문구가 그 명령을 알려 준다.
"""

import shutil

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.litellm_admin import LiteLLMError

KIND = "operational_check"
MIN_FREE_RATIO = 0.10
MIN_FREE_BYTES = 1 << 30
CHECKS = ("litellm", "key", "guardrail", "disk")


def key(check: str) -> str:
    return f"{KIND}:{check}"


def findings(litellm, export_dir) -> dict[str, str | None]:
    """점검 이름 -> 문제 설명(없으면 None). LiteLLM에 닿지 않으면 이어지는 점검은 건너뛴다."""
    out: dict[str, str | None] = {name: None for name in CHECKS}
    free = shutil.disk_usage(export_dir)
    if free.free < MIN_FREE_BYTES or free.free < free.total * MIN_FREE_RATIO:
        out["disk"] = f"여유 {free.free >> 20}MiB"
    if litellm is None:
        return out
    try:
        guardrails = litellm.list_guardrails()
    except LiteLLMError as error:
        if "HTTP 401" in str(error) or "HTTP 403" in str(error):
            out["key"] = "제어 키가 거부됩니다. 자동 복구 대기(10분 이내)"
        else:
            out["litellm"] = "LiteLLM에 연결할 수 없습니다."
        return out
    names = [
        g.get("guardrail_name") for g in guardrails
        if str((g.get("litellm_params") or {}).get("guardrail", "")).endswith(".MintGuardrail")
    ]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        out["guardrail"] = "중복 등록: " + ", ".join(map(str, dup))
    return out


def unverified_workers(conn, instance_id) -> int:
    """가장 최근 자가 점검이 실패한 워커 수."""
    row = fetchone(
        conn,
        "SELECT count(*) FROM (SELECT DISTINCT ON (payload->>'worker_id') kind FROM mint.events"
        " WHERE instance_id = %s AND kind IN ('enforcement_verified', 'enforcement_unverified')"
        " ORDER BY payload->>'worker_id', inserted_at DESC, event_id DESC) t"
        " WHERE kind = 'enforcement_unverified'", (instance_id,),
    )
    return int(row["count"]) if row else 0


def run(job) -> None:
    key_ = "enforcement_unverified:selfcheck"
    count = unverified_workers(job.conn, job.instance_id)
    if count:
        alerts.raise_alert(
            job.conn, job.instance_id, kind="enforcement_unverified", severity="critical",
            dedup_key=key_, subject={"workers": count},
        )
    else:
        alerts.resolve(job.conn, job.instance_id, key_)
    for check, problem in findings(job.litellm, job.settings.export_dir).items():
        if problem is None:
            alerts.resolve(job.conn, job.instance_id, key(check))
        else:
            alerts.raise_alert(
                job.conn, job.instance_id, kind=KIND, dedup_key=key(check),
                severity="medium" if check == "disk" else "high",
                subject={"check": check, "detail": problem},
            )
