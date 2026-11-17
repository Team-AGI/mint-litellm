"""단말 로컬 신청의 실행 묶음 화면 자료. 묶음 열이 없는 DB에서는 아무것도 읽지 않는다."""

from __future__ import annotations

from typing import Any

from mint_litellm.control.db.connection import fetchone

COLUMN = "pack_sha256"


def has_pack_columns(conn: Any) -> bool:
    row = fetchone(
        conn,
        "SELECT 1 AS found FROM information_schema.columns WHERE table_schema = 'mint'"
        " AND table_name = 'deployment_contracts' AND column_name = %s",
        (COLUMN,),
    )
    return row is not None


def read(conn: Any, instance: str, server_id: str, *, approved: bool = False) -> dict | None:
    """서버의 가장 최근 묶음 행. approved이면 승인된 계약만."""
    if not has_pack_columns(conn):
        return None
    where = " AND status = 'approved'" if approved else ""
    return fetchone(
        conn,
        "SELECT status, pack_spec, pack_sha256, pack_manifest, exec_contract"
        " FROM mint.deployment_contracts WHERE instance_id = %s AND server_id = %s"
        " AND (pack_spec IS NOT NULL OR pack_sha256 IS NOT NULL)" + where +
        " ORDER BY id DESC LIMIT 1",
        (instance, server_id),
    )


def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def stages(intake_status: str, has_pack: bool) -> list[tuple[str, str]]:
    """접수·묶음 준비·검사 단계 표시."""
    if intake_status == "failed":
        return [("ok", "접수"), ("ok" if has_pack else "error", "묶음 준비"), ("error", "검사")]
    prepared = ("ok", "묶음 준비") if has_pack else ("wait", "묶음 준비")
    if not has_pack:
        return [("ok", "접수"), prepared, ("off", "검사")]
    if intake_status in ("received", "checking"):
        return [("ok", "접수"), prepared, ("wait", "검사")]
    return [("ok", "접수"), prepared, ("ok", "검사")]


def view(row: dict | None, intake_status: str) -> dict:
    """화면용 묶음 정보. 행이 없으면 단계만."""
    row = row or {}
    has_pack = bool(row.get("pack_sha256"))
    manifest = _obj(row.get("pack_manifest"))
    spec = _obj(row.get("pack_spec"))
    contract = _obj(row.get("exec_contract"))
    package = _obj(manifest.get("package")) or spec
    files = [
        {"name": f.get("name"), "size": f.get("size"), "sha": str(f.get("sha256") or "")[:12]}
        for f in manifest.get("files") or []
        if isinstance(f, dict)
    ]
    access = contract.get("file_access", spec.get("file_access")) or []
    network = contract.get("network", spec.get("network")) or "none"
    return {
        "stages": stages(intake_status, has_pack),
        "ready": has_pack,
        "name": package.get("name"),
        "version": package.get("version"),
        "sha": row.get("pack_sha256"),
        "sha12": str(row.get("pack_sha256") or "")[:12],
        "files": files,
        "entry": manifest.get("entry") or _obj(contract.get("pack")).get("entry"),
        "access": [a for a in access if isinstance(a, dict)],
        "network": network,
        "hosts": contract.get("allowed_hosts", spec.get("allowed_hosts")) or [],
        "env": sorted((contract.get("env") or spec.get("env") or {}).items()),
        "runtime": contract.get("executable"),
        "reported_tools": [t for t in spec.get("observed_tools") or [] if isinstance(t, dict)],
        "network_choices": narrower_networks(network),
    }


def narrower_networks(current: str) -> list[tuple[str, str]]:
    """지금 값보다 넓지 않은 네트워크 선택지(유지 포함)."""
    keep = ("keep", "지금 그대로")
    if current == "none":
        return [keep]
    return [keep, ("none", "차단")]
