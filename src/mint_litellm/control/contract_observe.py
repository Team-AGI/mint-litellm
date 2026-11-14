"""업스트림 원본 관측과 플러그인 배포 관측 사건의 소비."""

import json
import re
import uuid
from collections.abc import Collection, Iterable
from datetime import UTC, datetime
from typing import Any

from mint_litellm.control import alerts, change_summary
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict
from mint_litellm.control.intake_checks import SERVER_CREDENTIAL_FLOW
from mint_litellm.control.intake_jobs import _oauth_config_read
from mint_litellm.control.services import intakes
from mint_litellm.control.services.base import transact
from mint_litellm.types.canonical import canonical_text, sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7


def normalize_tools(body: Any) -> dict[str, dict]:
    """불완전한 목록을 도구 삭제로 오인하지 않도록 전체 응답을 먼저 검사한다."""
    if (
        not isinstance(body, dict)
        or body.get("error")
        or body.get("status") == "error"
        or not isinstance(body.get("tools"), list)
    ):
        raise ValueError("upstream tool listing failed")
    if len(body["tools"]) > 500 or len(canonical_text(body).encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("upstream tool listing exceeds limits")

    def depth(value: Any, level: int = 0) -> None:
        if level > 20:
            raise ValueError("upstream tool listing exceeds nesting limit")
        if isinstance(value, dict):
            for item in value.values():
                depth(item, level + 1)
        elif isinstance(value, list):
            for item in value:
                depth(item, level + 1)

    depth(body)
    result = {}
    for tool in body["tools"]:
        name = tool.get("name") if isinstance(tool, dict) else None
        schema = tool.get("inputSchema", tool.get("input_schema")) if name else None
        if not isinstance(name, str) or not name or name in result or not isinstance(schema, dict):
            raise ValueError("invalid or duplicate upstream tool")
        value = {"description": tool.get("description") or "", "input_schema": schema}
        if not isinstance(value["description"], str):
            raise ValueError("tool description must be text")
        for source, dest in (
            ("annotations", "annotations"),
            ("outputSchema", "output_schema"),
            ("output_schema", "output_schema"),
        ):
            if tool.get(source) is not None:
                if not isinstance(tool[source], dict):
                    raise ValueError("tool schemas and annotations must be objects")
                value[dest] = tool[source]
        result[name] = value
    return result


def drift_kind(approved: dict, observed: dict | None) -> str:
    if observed is None:
        return "removed"
    if approved.get("input_schema") != observed.get("input_schema"):
        return "input_schema"
    if any(approved.get(k) != observed.get(k) for k in ("description", "annotations")):
        return "description"
    if "output_schema" in approved and approved["output_schema"] != observed.get("output_schema"):
        return "output_schema"
    return "none"


def _observe(
    ctx: Context,
    server_id: str,
    kind: str,
    scope: str,
    name: str,
    entity_id: Any,
    value: Any,
    *,
    is_drift: bool = True,
    summary: str | None = None,
) -> tuple[dict, bool]:
    row = fetchone(
        ctx.conn,
        "SELECT * FROM mint.contract_observations WHERE instance_id=%s AND server_id=%s"
        " AND kind=%s AND scope=%s AND name=%s FOR UPDATE",
        (ctx.instance_id, server_id, kind, scope, name),
    )
    digest, text = sha256(value), canonical_text(value)
    changed = row is None or row["observed_sha256"] != digest or row["entity_id"] != entity_id
    seq = (
        int(is_drift)
        if row is None or row["entity_id"] != entity_id
        else row["change_seq"] + int(changed and is_drift)
    )
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.contract_observations"
        " (instance_id,server_id,kind,scope,name,entity_id,observed_sha256,"
        " canonical_text,change_seq,change_summary)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        " ON CONFLICT (instance_id,server_id,kind,scope,name) DO UPDATE SET"
        " entity_id=EXCLUDED.entity_id, observed_sha256=EXCLUDED.observed_sha256,"
        " canonical_text=EXCLUDED.canonical_text,change_seq=EXCLUDED.change_seq,observed_at=now(),"
        " change_summary=EXCLUDED.change_summary"
        " RETURNING *",
        (ctx.instance_id, server_id, kind, scope, name, entity_id, digest, text, seq, summary),
    )
    return row, changed


def _alert(ctx: Context, entity_id: Any, digest: str, severity: str, payload: dict) -> None:
    """계약 드리프트 경보. 단일 경로 ``raise_alert``라 새 경보마다 ``alert_opened``가 남는다."""
    alerts.raise_alert(
        ctx.conn, ctx.instance_id, kind="contract_drift", severity=severity,
        dedup_key=f"contract_drift:{entity_id}:{digest}", subject=payload)


def record_tools(
    ctx: Context, server_id: str, scope: str, tools: dict[str, dict], expected_version: int,
    *, local: bool = False,
) -> None:
    """외부 읽기 뒤 서버 버전을 확인하며 관측·드리프트·사건을 원자적으로 기록한다.

    ``local``이면 계약 관리가 아닌 로컬(stdio) 서버도 다룬다(단말이 보고한 목록).
    """
    with transact(ctx):
        server = fetchone(
            ctx.conn,
            "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        if server is None or (
            server["contract_status"] != "managed"
            and not (local and server["identity_kind"] == "stdio")
        ):
            return
        if server["state_version"] != expected_version:
            raise conflict("관측 중 서버가 변경되었습니다.")
        approved = {
            c["tool"]: c
            for c in fetchall(
                ctx.conn,
                "SELECT * FROM mint.tool_contracts WHERE instance_id=%s AND server_id=%s"
                " AND credential_scope=%s AND status='approved'",
                (ctx.instance_id, server_id, scope),
            )
        }
        recheck = False
        for name in sorted(approved.keys() | tools.keys()):
            contract, value = approved.get(name), tools.get(name)
            entity = contract["id"] if contract else new_uuid7()
            previous = fetchone(
                ctx.conn,
                "SELECT entity_id FROM mint.contract_observations WHERE instance_id=%s"
                " AND server_id=%s AND kind='tool' AND scope=%s AND name=%s",
                (ctx.instance_id, server_id, scope, name),
            )
            if contract is None and previous:
                entity = previous["entity_id"]
            drift = (
                drift_kind(json.loads(contract["canonical_text"]), value) if contract else "added"
            )
            observation, changed = _observe(
                ctx, server_id, "tool", scope, name, entity, value, is_drift=drift != "none",
                summary=(
                    change_summary.tool_summary(contract["canonical_text"] if contract else None,
                                                value)
                    if drift != "none" else None
                ),
            )
            if contract:
                # 입력 변경 차단은 재승인 전까지 유지한다.
                effective = "input_schema" if contract["drift"] == "input_schema" else drift
                updated = fetchone(
                    ctx.conn,
                    "UPDATE mint.tool_contracts SET drift=%s,observed_sha256=%s,"
                    " observed_at=now() WHERE instance_id=%s AND id=%s RETURNING version",
                    (
                        effective if drift != "removed" else "removed",
                        observation["observed_sha256"],
                        ctx.instance_id,
                        entity,
                    ),
                )
                contract["version"] = updated["version"]
            if changed and drift != "none":
                payload = {
                    "server_id": server_id,
                    "tool": name,
                    "credential_scope": scope,
                    "drift": drift,
                    "observed_sha256": observation["observed_sha256"],
                    "version": contract["version"] if contract else None,
                }
                ctx.emit(
                    EventKind.CONTRACT_DRIFT_DETECTED, entity, observation["change_seq"], payload
                )
                ctx.emit(EventKind.REAPPROVAL_REQUESTED, entity, observation["change_seq"], payload)
                _alert(
                    ctx,
                    entity,
                    observation["observed_sha256"],
                    {"input_schema": "high", "added": "low", "removed": "low"}.get(drift, "medium"),
                    payload,
                )
                recheck = recheck or drift != "removed"
            if contract and drift == "removed":
                row = fetchone(
                    ctx.conn,
                    "UPDATE mint.tool_contracts SET status='superseded'"
                    " WHERE instance_id=%s AND id=%s RETURNING version",
                    (ctx.instance_id, entity),
                )
                ctx.emit(
                    EventKind.CONTRACT_SUPERSEDED,
                    entity,
                    row["version"],
                    {"server_id": server_id, "cause": "removed"},
                )
        ctx.conn.execute(
            "UPDATE mint.servers SET last_observed_at=now() WHERE instance_id=%s AND server_id=%s",
            (ctx.instance_id, server_id),
        )
        if recheck and not local:  # 새 드리프트마다 승인한 신청의 재검사(후보 계약 생산)를 등록한다
            intakes.enqueue_drift_recheck(ctx, server_id)


def consume_deployment_events(ctx: Context) -> None:
    rows = fetchall(
        ctx.conn,
        "SELECT e.event_id,e.payload FROM mint.events e WHERE e.instance_id=%s"
        " AND e.kind='server_identity_mismatch_observed' AND NOT EXISTS"
        " (SELECT 1 FROM mint.contract_observation_receipts r"
        " WHERE r.instance_id=e.instance_id AND r.event_id=e.event_id)"
        " ORDER BY e.inserted_at,e.event_id",
        (ctx.instance_id,),
    )
    for event in rows:
        with transact(ctx):
            payload = event["payload"]
            server_id = payload.get("server_id")
            server = fetchone(
                ctx.conn,
                "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
                (ctx.instance_id, server_id),
            )
            receipt = ctx.conn.execute(
                "INSERT INTO mint.contract_observation_receipts"
                " (instance_id,event_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                (ctx.instance_id, event["event_id"]),
            )
            if receipt.rowcount != 1 or not server or server["contract_status"] != "managed":
                continue
            hashes = payload.get("observed_hashes", {})
            if (
                not isinstance(hashes, dict)
                or not hashes
                or any(
                    key
                    not in {"url_sha256", "transport", "auth_type", "issuer", "registry_missing"}
                    or not isinstance(value, str)
                    or not re.fullmatch("[0-9a-f]{64}", value)
                    for key, value in hashes.items()
                )
            ):
                continue
            contract = fetchone(
                ctx.conn,
                "SELECT * FROM mint.deployment_contracts"
                " WHERE instance_id=%s AND server_id=%s AND status='approved'",
                (ctx.instance_id, server_id),
            )
            if contract is None:
                continue
            _deployment_drift(ctx, server, contract, "identity", hashes, sorted(hashes))


# 연속으로 이만큼 읽지 못해야 차단한다(일시적 장애는 경보만)
OAUTH2_READ_FAILURES = 3


def _deployment_drift(
    ctx: Context, server: dict, contract: dict, name: str, value: Any, fields: list[str],
    entity: Any = None,
) -> None:
    """배포 드리프트 표지를 켜고(호출 차단), 값이 바뀐 때마다 사건·재승인 요청·경보를 낸다."""
    server_id = server["server_id"]
    entity = entity or contract["id"]  # 사건·경보 키의 개체(관측 이름마다 순번이 따로 올라간다)
    observation, changed = _observe(ctx, server_id, "deployment", "server", name,
                                    contract["id"], value,
                                    summary=change_summary.deployment_summary(fields))
    merged = sorted(set(server["deployment_drift_fields"] or ()) | set(fields))
    if not server["deployment_drift"] or merged != server["deployment_drift_fields"]:
        ctx.conn.execute(
            "UPDATE mint.servers SET deployment_drift=true,"
            " deployment_drift_fields=%s WHERE instance_id=%s AND server_id=%s",
            (merged, ctx.instance_id, server_id),
        )
    if changed:
        body = {
            "server_id": server_id,
            "fields": sorted(fields),
            "observed_sha256": observation["observed_sha256"],
            "version": contract["version"],
            "kind": "deployment",
        }
        ctx.emit(EventKind.DEPLOYMENT_DRIFT_DETECTED, entity, observation["change_seq"], body)
        ctx.emit(EventKind.REAPPROVAL_REQUESTED, entity, observation["change_seq"], body)
        _alert(ctx, entity, observation["observed_sha256"], "critical", body)
        intakes.enqueue_drift_recheck(ctx, server_id)


def record_oauth2_flow(
    ctx: Context, server_id: str, flow: str | None, readable: bool = True
) -> bool:
    """승인된 배포 계약이 oauth2인 서버의 관측된 ``oauth2_flow``를 판정한다.

    읽은 값이 서버 자격 흐름이 아니면(없는 값 포함) 바로 배포 드리프트를 켠다. 읽지 못했으면
    경보만 내고, 연속 ``OAUTH2_READ_FAILURES``번째 실패부터 드리프트를 켠다. 서버 자격 흐름이면
    실패 횟수만 지우고 아무것도 바꾸지 않는다(이미 켜진 표지는 재승인으로만 꺼진다).
    드리프트를 켰으면 참이다.
    """
    with transact(ctx):
        server = fetchone(
            ctx.conn,
            "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        contract = fetchone(
            ctx.conn,
            "SELECT * FROM mint.deployment_contracts"
            " WHERE instance_id=%s AND server_id=%s AND status='approved'",
            (ctx.instance_id, server_id),
        )
        if (
            server is None or server["contract_status"] != "managed" or contract is None
            or contract["auth_type"] != "oauth2"
        ):
            return False
        row = fetchone(
            ctx.conn,
            "SELECT canonical_text, entity_id FROM mint.contract_observations WHERE instance_id=%s"
            " AND server_id=%s AND kind='deployment' AND scope='server'"
            " AND name='oauth2_flow_read'",
            (ctx.instance_id, server_id),
        )
        # 실패 횟수는 지금 승인된 계약에 대해서만 센다(재승인하면 새로 센다).
        failures = (
            json.loads(row["canonical_text"])["failures"]
            if row and row["entity_id"] == contract["id"] else 0
        )
        if readable and flow == SERVER_CREDENTIAL_FLOW:
            if failures:
                _observe(ctx, server_id, "deployment", "server", "oauth2_flow_read",
                         contract["id"], {"failures": 0}, is_drift=False)
            return False
        if readable:
            value = {"oauth2_flow": flow} if flow else {"oauth2_flow_missing": True}
        else:
            failures += 1
            _observe(ctx, server_id, "deployment", "server", "oauth2_flow_read",
                     contract["id"], {"failures": failures}, is_drift=False)
            if failures < OAUTH2_READ_FAILURES:
                alerts.raise_alert(
                    ctx.conn, ctx.instance_id, kind="oauth_flow_unreadable", severity="medium",
                    dedup_key=f"oauth_flow_unreadable:{server_id}",
                    subject={"server_id": server_id, "failures": failures})
                return False
            value = {"oauth_flow_unreadable": True}
        _deployment_drift(ctx, server, contract, "oauth2_flow", value, ["oauth2_flow"],
                          entity=uuid.uuid5(contract["id"], "oauth2_flow"))
    return True


def record_oauth_scopes(ctx: Context, server_id: str, scopes: list[str]) -> bool:
    """서버 정의의 OAuth 범위가 승인된 배포 계약보다 넓으면 배포 드리프트를 켠다(호출 차단).

    승인 범위에 없는 범위가 하나라도 있으면 넓어진 것이다. 같거나 좁아지면 아무것도 하지 않는다.
    넓어졌으면 참이다.
    """
    with transact(ctx):
        server = fetchone(
            ctx.conn,
            "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        contract = fetchone(
            ctx.conn,
            "SELECT * FROM mint.deployment_contracts"
            " WHERE instance_id=%s AND server_id=%s AND status='approved'",
            (ctx.instance_id, server_id),
        )
        if server is None or server["contract_status"] != "managed" or contract is None:
            return False
        wider = sorted(set(scopes) - set(contract["oauth_scopes"] or ()))
        if not wider:
            return False
        _deployment_drift(ctx, server, contract, "oauth_scopes", {"wider_oauth_scopes": wider},
                          ["oauth_scopes"], entity=uuid.uuid5(contract["id"], "oauth_scopes"))
    return True


def instance_differences(
    instances: Collection[str], rows: Iterable[tuple[str, str, str, str]]
) -> list[dict]:
    """인스턴스마다 승인 계약의 해시가 하나로 모이지 않는 항목.

    ``rows``는 (인스턴스, 종류, 항목, 해시)이다. 어떤 인스턴스에 없는 항목은 해시가 None이라
    있는 인스턴스와 다른 것으로 본다.
    """
    table: dict[tuple[str, str], dict[str, str]] = {}
    for instance, kind, item, digest in rows:
        table.setdefault((kind, item), {})[instance] = digest
    names = sorted(instances)
    return [
        {"kind": kind, "item": item, "digests": {i: by.get(i) for i in names}}
        for (kind, item), by in sorted(table.items())
        if len({by.get(i) for i in names}) > 1
    ]


_APPROVED_CONTRACTS = (
    "SELECT d.instance_id, 'deployment' AS kind, '' AS item, d.sha256"
    " FROM mint.deployment_contracts d WHERE d.server_id=%s AND d.status='approved'"
    " AND d.instance_id = ANY(%s)"
    " UNION ALL"
    " SELECT t.instance_id, 'tool', t.credential_scope || '/' || t.tool, t.sha256"
    " FROM mint.tool_contracts t WHERE t.server_id=%s AND t.status='approved'"
    " AND t.instance_id = ANY(%s)"
    " UNION ALL"
    " SELECT instance_id, 'setting', 'guardrail_mode', mode FROM mint.settings"
    " WHERE instance_id = ANY(%s)"
    " UNION ALL"
    " SELECT instance_id, 'setting', 'policy_bundle', bundle_sha256 FROM mint.policy_versions"
    " WHERE status='active' AND instance_id = ANY(%s)"
)


def _excepted(ctx: Context, server_id: str) -> bool:
    """이 서버에 지금 유효한 ``instance_exception`` 증빙(admin이 기록한 예외)이 있는가."""
    row = fetchone(
        ctx.conn,
        "SELECT valid_until FROM mint.policy_evidence WHERE instance_id=%s"
        " AND kind='instance_exception' AND subject_kind='server' AND subject_id=%s"
        " ORDER BY attached_at DESC, id DESC LIMIT 1",
        (ctx.instance_id, server_id),
    )
    until = row["valid_until"] if row else None
    return row is not None and (until is None or until > datetime.now(UTC))


def _track(ctx: Context, server_id: str, differing: bool, grace_seconds: int) -> None:
    """차이를 처음 본 시각을 남기고, 유예(``grace_seconds``)가 지나도 남아 있고 예외 증빙이 없으면
    막는 표지를 올린다. 차이가 사라지면 둘 다 비운다. 값이 바뀔 때만 쓴다(서버 행 갱신은 판정
    스냅숏을 새로 만든다)."""
    row = fetchone(
        ctx.conn,
        "SELECT instance_mismatch_since AS since, instance_mismatch_at AS at,"
        " coalesce(instance_mismatch_since, now()) <= now() - %s * interval '1 second' AS due"
        " FROM mint.servers WHERE instance_id=%s AND server_id=%s",
        (grace_seconds, ctx.instance_id, server_id),
    )
    if row is None:
        return
    block = differing and row["due"] and not _excepted(ctx, server_id)
    if (row["since"] is not None) == differing and (row["at"] is not None) == block:
        return
    ctx.conn.execute(
        "UPDATE mint.servers SET"
        " instance_mismatch_since = CASE WHEN %s THEN coalesce(instance_mismatch_since, now()) END,"
        " instance_mismatch_at = CASE WHEN %s THEN coalesce(instance_mismatch_at, now()) END"
        " WHERE instance_id=%s AND server_id=%s",
        (differing, block, ctx.instance_id, server_id),
    )


def compare_instances(ctx: Context, grace_seconds: int = 0) -> int:
    """같은 서버를 계약 관리하는 다른 인스턴스의 승인 계약(배포·도구 정의)과 보안 설정(가드레일
    모드·활성 정책 묶음)을 비교한다.

    어긋나면 경보와 배포 변경 사건을 바로 내고, 차이가 ``grace_seconds`` 넘게 남으면 이
    인스턴스의 그 서버 호출을 막는다(차이를 처음 본 시각부터 센다. 0이면 바로 막는다).
    기준 인스턴스는 두지 않는다: 어긋난 쪽 모두가 막히며 admin의 ``instance_exception``
    증빙이 있거나
    차이가 사라지면 풀린다.
    같은 서버를 쓰는 인스턴스가 하나뿐이면 아무 영향이 없다. 어긋난 서버 수를 돌려준다.
    """
    mine = fetchall(
        ctx.conn,
        "SELECT server_id FROM mint.servers WHERE instance_id=%s AND status='approved'"
        " AND contract_status='managed' ORDER BY server_id",
        (ctx.instance_id,),
    )
    mismatched = 0
    for row in mine:
        server_id = row["server_id"]
        with transact(ctx):
            peers = [
                r["instance_id"]
                for r in fetchall(
                    ctx.conn,
                    "SELECT instance_id FROM mint.servers WHERE server_id=%s AND status='approved'"
                    " AND contract_status='managed' ORDER BY instance_id",
                    (server_id,),
                )
            ]
            key = f"instance_mismatch:{server_id}"
            differences = (
                instance_differences(
                    peers,
                    (
                        (r["instance_id"], r["kind"], r["item"], r["sha256"])
                        for r in fetchall(
                            ctx.conn, _APPROVED_CONTRACTS,
                            (server_id, peers, server_id, peers, peers, peers),
                        )
                    ),
                )
                if len(peers) > 1
                else []
            )
            entity = uuid.uuid5(uuid.NAMESPACE_OID, f"{ctx.instance_id}/{server_id}/instances")
            observation, changed = _observe(
                ctx, server_id, "deployment", "server", "instance_compare", entity,
                {"instances": peers, "differences": differences}, is_drift=bool(differences),
            )
            if not differences:
                alerts.resolve(ctx.conn, ctx.instance_id, key)
                _track(ctx, server_id, False, grace_seconds)
                continue
            mismatched += 1
            _track(ctx, server_id, True, grace_seconds)
            body = {
                "server_id": server_id,
                "kind": "instance_mismatch",
                "instances": peers,
                "items": [f"{d['kind']}:{d['item']}".rstrip(":") for d in differences],
                "observed_sha256": observation["observed_sha256"],
            }
            if changed:
                ctx.emit(
                    EventKind.DEPLOYMENT_DRIFT_DETECTED, entity, observation["change_seq"], body
                )
            alerts.raise_alert(
                ctx.conn, ctx.instance_id, kind="instance_mismatch", severity="high",
                dedup_key=key, subject={**body, "differences": differences},
            )
    return mismatched


def handle(job) -> None:
    from mint_litellm.control import local_tools
    from mint_litellm.types.canonical import credential_scope

    ctx = Context(job.conn, job.instance_id, Operator("contract-observer", "admin", None))
    consume_deployment_events(ctx)
    local_tools.consume(ctx)
    compare_instances(ctx, job.settings.instance_mismatch_grace_seconds if job.settings else 900)
    servers = fetchall(
        job.conn,
        "SELECT s.server_id,d.auth_type,s.state_version,d.url,d.transport"
        " FROM mint.servers s LEFT JOIN mint.deployment_contracts d"
        " ON d.instance_id=s.instance_id AND d.server_id=s.server_id AND d.status='approved'"
        " WHERE s.instance_id=%s AND s.contract_status='managed' AND s.status='approved'"
        " AND (%s='contract_observe' OR s.server_id=%s) ORDER BY s.server_id",
        (job.instance_id, job.job["target_ref"], job.job["target_ref"]),
    )
    if not servers:
        return
    if job.litellm is None:
        raise ControlError("MINT_LITELLM_URL과 MINT_LITELLM_KEY가 필요합니다.")
    test_tools_list = job.litellm.test_tools_list
    failed = False
    for server in servers:
        job.checkpoint()
        # 시험 목록 API는 수용검증 클라이언트와 공유한다. served 목록을 대신 읽지 않는다.
        # LiteLLM은 서버 식별자만으로는 접속 대상을 알지 못해 승인된 배포 값(URL·전송·인증)을 함께
        # 보낸다. 식별자는 레지스트리에 저장된 자격을 쓰게 한다.
        try:
            if not server["url"]:
                raise ValueError("no approved deployment contract")
            body = test_tools_list(
                {
                    "server_id": server["server_id"],
                    "url": server["url"],
                    "transport": server["transport"],
                    "auth_type": server["auth_type"],
                }
            )
            tools = normalize_tools(body)
            job.checkpoint()
            record_tools(
                ctx,
                server["server_id"],
                credential_scope(server["auth_type"]),
                tools,
                server["state_version"],
            )
        except (ControlError, ValueError):
            failed = True
        if server["auth_type"] == "oauth2":
            # 서버 자격 흐름이 아니거나 읽지 못하면 차단한다(30일 증거 재검사를 기다리지 않는다).
            # 표지가 서버 판본을 올리므로 도구 관측이 끝난 뒤에 한다.
            job.checkpoint()
            flow, scopes, readable = _oauth_config_read(
                job.litellm, server["server_id"], frozenset({"approved"}))
            if not record_oauth2_flow(ctx, server["server_id"], flow, readable) and readable:
                record_oauth_scopes(ctx, server["server_id"], scopes)
    if failed:
        raise ControlError("일부 서버의 계약 관측이 실패했습니다.")
