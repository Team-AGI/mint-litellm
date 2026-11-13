"""서버 등록과 중지·재개.

서버의 계약 값(URL 해시·전송 방식·인증 방식)은 등록 시점의 LiteLLM 레지스트리 값이다.
호출 시점의 레지스트리 값과 하나라도 다르면 플러그인이 호출을 차단한다. 로컬 실행(stdio) 서버는
LiteLLM 레지스트리 없이 실행 계약 해시만 MINT 표에 등록한다.
"""

from collections.abc import Mapping
from typing import Any

from mint_litellm.control import alerts, exec_drift, packages
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.types.decision import normalize_auth_type, url_sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.exec_contract import ExecContract
from mint_litellm.types.ids import new_uuid7


def _config_url(config: Mapping[str, Any] | None, server_id: str) -> str | None:
    """LiteLLM 설정 파일에서 ``server_id``가 같은 설정 서버의 URL."""
    for server in ((config or {}).get("mcp_servers") or {}).values():
        if isinstance(server, Mapping) and server.get("server_id") == server_id:
            url = server.get("url")
            return url if isinstance(url, str) and url else None
    return None


def register(
    ctx: Context,
    litellm: LiteLLMAdmin,
    server_id: str,
    url: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> None:
    """서버를 등록한다. 계약 URL은 운영자 지정, 설정 파일, 관리 API 응답 순으로 정한다.

    둘 이상의 출처가 보이면 모두 같아야 한다. 제어 평면 키에는 관리 API가 URL을 응답하지
    않으므로 보통 앞의 두 출처 중 하나가 쓰인다.
    """
    entry = litellm.get_server(server_id)
    if entry is None:
        raise ControlError(f"LiteLLM에 서버 {server_id}이(가) 없습니다.")
    if entry.get("approval_status") not in (None, "active", "approved"):
        raise ControlError(
            f"서버 {server_id}는 LiteLLM에서 아직 승인되지 않았습니다"
            f"(approval_status={entry.get('approval_status')})."
        )
    if entry.get("transport") == "stdio" or entry.get("spec_path") or entry.get("command"):
        raise ControlError(
            "MINT-UNSUPPORTED: server_without_url — URL이 없는 서버(stdio, OpenAPI 명세 기반)는 "
            "등록할 수 없습니다. 계약 값을 URL 해시로 정하므로 HTTP URL로 연결되는 서버만 "
            "이 명령으로 통제할 수 있습니다. 로컬 실행 서버는 server register-local로 "
            "실행 계약을 등록하십시오."
        )
    found = [
        (source, value)
        for source, value in (
            ("operator", url),
            ("config_file", _config_url(config, server_id)),
            ("registry", entry.get("url")),
        )
        if value
    ]
    if len({value for _, value in found}) > 1:
        raise ControlError(
            "서버 URL의 출처가 서로 다릅니다: " + ", ".join(source for source, _ in found)
            + ". --url, 설정 파일, LiteLLM 레지스트리 값을 확인하십시오."
        )
    if not found:
        raise ControlError(
            "제어 평면 키에는 서버 URL이 응답되지 않습니다. 계약 값에 쓸 URL을 --url로 지정하거나 "
            "--config로 LiteLLM 설정 파일을 지정하십시오(호출 시점에 레지스트리 값과 다르면 "
            "호출이 차단됩니다)."
        )
    url_source, resolved = found[0]
    transport = entry.get("transport")
    if not transport:
        raise ControlError(f"서버 {server_id}의 전송 방식을 읽을 수 없습니다.")
    auth_type = normalize_auth_type(entry.get("auth_type"))
    digest = url_sha256(resolved)
    payload = {
        "server_id": server_id,
        "url_sha256": digest,
        "transport": transport,
        "auth_type": auth_type,
        "url_source": url_source,
    }
    existing = fetchone(
        ctx.conn,
        "SELECT id, status, identity_kind FROM mint.servers"
        " WHERE instance_id = %s AND server_id = %s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    if existing:
        if existing["identity_kind"] != "remote":
            raise ControlError(f"서버 {server_id}는 로컬 실행 서버라 URL로 바꿀 수 없습니다.")
        # 이미 등록된 서버의 재등록은 계약 값을 갱신한다(URL 변경 등). 상태는 바꾸지 않는다.
        if existing["status"] in ("rejected", "terminating", "terminated"):
            raise ControlError(
                f"서버 {server_id}는 {existing['status']} 상태라 갱신할 수 없습니다."
            )
        row = fetchone(
            ctx.conn,
            "UPDATE mint.servers SET url_sha256 = %s, transport = %s, auth_type = %s"
            " WHERE id = %s RETURNING state_version",
            (digest, transport, auth_type, existing["id"]),
        )
        ctx.emit(EventKind.SERVER_REGISTERED, existing["id"], row["state_version"],
                 {**payload, "updated": True})
        return
    row_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
        " auth_type, registered_by) VALUES (%s, %s, %s, 'awaiting_approval', %s, %s, %s, %s)"
        " RETURNING state_version",
        (row_id, ctx.instance_id, server_id, digest, transport, auth_type, ctx.operator.name),
    )
    ctx.emit(EventKind.SERVER_REGISTERED, row_id, row["state_version"], payload)


def _exec_drift(ctx: Context, server_id: str, old_sha: str, contract: ExecContract) -> dict:
    """계약 해시가 바뀌면 이전 계약과 축별로 비교해 경보를 낸다(호출 차단은 해시 결속이 맡는다)."""
    if old_sha == contract.sha256():
        return {}
    previous = fetchone(
        ctx.conn,
        "SELECT payload -> 'exec_contract' AS contract FROM mint.events"
        " WHERE instance_id = %s AND kind = 'server_registered'"
        " AND payload ->> 'server_id' = %s AND payload ->> 'exec_contract_sha256' = %s"
        " ORDER BY inserted_at DESC LIMIT 1",
        (ctx.instance_id, server_id, old_sha),
    )
    if previous is None or not isinstance(previous["contract"], dict):
        return {}  # 이전 계약 원문을 찾지 못하면 비교하지 못한다(해시 결속으로는 이미 차단된다)
    result = exec_drift.classify(previous["contract"], contract.document())
    widened = exec_drift.widened_axes(result)
    changed = packages.changes(previous["contract"], contract.document())
    subject = {
        "kind": "exec", "server_id": server_id, "axes": result, "widened": widened,
        "summary": exec_drift.summary(result, changed), "package_changes": changed,
    }
    alerts.raise_alert(
        ctx.conn, ctx.instance_id, kind="contract_drift", severity="high" if widened else "low",
        dedup_key=f"contract_drift:exec:{server_id}:{contract.sha256()}", subject=subject)
    return {"exec_drift": {"axes": result, "widened": widened, "package_changes": changed}}


def _record_packages(ctx: Context, server_id: str, contract: ExecContract) -> None:
    """계약의 패키지(제공처·이름·버전)를 적고, 버전이 고정되지 않은 것이 있으면 경보를 연다."""
    found = packages.extract(contract.document())
    for p in found:
        ctx.conn.execute(
            "INSERT INTO mint.server_packages (id, instance_id, server_id, exec_contract_sha256,"
            " ecosystem, name, version, pinned, registry) VALUES (%s, %s, %s, %s, %s, %s, %s, %s,"
            " %s) ON CONFLICT DO NOTHING",
            (new_uuid7(), ctx.instance_id, server_id, contract.sha256(), p.ecosystem, p.name,
             p.version, p.pinned, p.registry),
        )
    loose = packages.unpinned(found)
    key = f"package_unpinned:{server_id}"
    if loose:
        alerts.resolve(ctx.conn, ctx.instance_id, key)  # 계약이 바뀌었으면 새 내용으로 다시 연다
        alerts.raise_alert(
            ctx.conn, ctx.instance_id, kind="package_unpinned", severity="medium", dedup_key=key,
            subject={"server_id": server_id, "packages": [
                {"ecosystem": p.ecosystem, "name": p.name, "version": p.version,
                 "registry": p.registry} for p in loose]},
        )
    else:
        alerts.resolve(ctx.conn, ctx.instance_id, key)


def register_local(ctx: Context, server_id: str, contract: ExecContract) -> None:
    """로컬 실행(stdio) 서버를 LiteLLM 없이 승인 대기 상태로 등록한다.

    계약 값은 URL 해시가 아니라 실행 계약의 해시와 판본이다. 이미 등록된 로컬 서버에 다시
    실행하면 계약 값을 갱신하고 상태는 바꾸지 않는다(원격 서버의 재등록과 같다).
    """
    digest, version = contract.sha256(), contract.schema_version
    payload = {
        "server_id": server_id,
        "identity_kind": "stdio",
        "exec_contract_sha256": digest,
        "exec_contract_version": version,
        "transport": "stdio",
        "auth_type": "none",
        "exec_contract": contract.document(),
    }
    existing = fetchone(
        ctx.conn,
        "SELECT id, status, identity_kind, exec_contract_sha256 FROM mint.servers"
        " WHERE instance_id = %s AND server_id = %s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    if existing:
        if existing["identity_kind"] != "stdio":
            raise ControlError(f"서버 {server_id}는 원격 서버로 등록되어 있어 바꿀 수 없습니다.")
        if existing["status"] in ("rejected", "terminating", "terminated"):
            raise ControlError(
                f"서버 {server_id}는 {existing['status']} 상태라 갱신할 수 없습니다."
            )
        drift = _exec_drift(ctx, server_id, existing["exec_contract_sha256"], contract)
        row = fetchone(
            ctx.conn,
            "UPDATE mint.servers SET exec_contract_sha256 = %s, exec_contract_version = %s"
            " WHERE id = %s RETURNING state_version",
            (digest, version, existing["id"]),
        )
        ctx.emit(EventKind.SERVER_REGISTERED, existing["id"], row["state_version"],
                 {**payload, "updated": True, **drift})
        _record_packages(ctx, server_id, contract)
        return
    row_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.servers (id, instance_id, server_id, status, identity_kind,"
        " exec_contract_sha256, exec_contract_version, transport, auth_type, registered_by)"
        " VALUES (%s, %s, %s, 'awaiting_approval', 'stdio', %s, %s, 'stdio', 'none', %s)"
        " RETURNING state_version",
        (row_id, ctx.instance_id, server_id, digest, version, ctx.operator.name),
    )
    ctx.emit(EventKind.SERVER_REGISTERED, row_id, row["state_version"], payload)
    _record_packages(ctx, server_id, contract)


def _transition(ctx: Context, server_id: str, source: str, target: str, kind: EventKind) -> None:
    row = fetchone(
        ctx.conn,
        "UPDATE mint.servers SET status = %s WHERE instance_id = %s AND server_id = %s"
        " AND status = %s RETURNING id, state_version",
        (target, ctx.instance_id, server_id, source),
    )
    if row is None:
        raise not_found(f"{source} 상태의 서버 {server_id}이(가) 없습니다.")
    ctx.emit(kind, row["id"], row["state_version"], {"server_id": server_id, "status": target})


def suspend(ctx: Context, server_id: str) -> None:
    _transition(ctx, server_id, "approved", "suspended", EventKind.SERVER_SUSPENDED)


def resume(ctx: Context, server_id: str) -> None:
    _transition(ctx, server_id, "suspended", "approved", EventKind.SERVER_RESUMED)


def terminate(ctx: Context, server_id: str) -> None:
    """승인·중지 서버를 폐기 중으로 바꾼다. 자격 삭제와 확인은 ``server_finalize`` 작업이 한다."""
    status = fetchone(
        ctx.conn,
        "SELECT status FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (ctx.instance_id, server_id),
    )
    if status is None or status["status"] not in ("approved", "suspended"):
        raise not_found(f"승인 또는 중지 상태의 서버 {server_id}이(가) 없습니다.")
    _transition(ctx, server_id, status["status"], "terminating", EventKind.SERVER_TERMINATING)
