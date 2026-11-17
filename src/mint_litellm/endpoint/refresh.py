"""설치 보고 응답의 승인 서버 목록(``desired``)과, 단말이 보고한 로컬 MCP 항목의 병합.

``desired``는 MINT가 아는 승인 상태에서 만든다(단말의 주장이 아니다). 항목마다 서버 이름, 실행
계약, 계약의 판본(계약 내용의 해시)을 싣고, 실행기 인자는 단말이 자기 설치 경로로 만든다. 단말이
보고한 로컬 MCP 항목은 단말의 주장이며 이름·전송 종류·실행 파일 이름이나 호스트만 받는다.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from mint_litellm.endpoint.kit_build import approved_contracts

MAX_DESIRED = 256


def contract_version(contract: Mapping[str, Any]) -> str:
    """계약 내용의 판본. 단말 묶음의 같은 이름 함수와 같은 값을 낸다."""
    text = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def desired_servers(contracts: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """승인된 로컬 서버 계약에서 응답에 실을 목록(이름 순)."""
    checked = approved_contracts(contracts)
    return [
        {"name": name, "version": contract_version(contract), "contract": contract}
        for name, contract in list(checked.items())[:MAX_DESIRED]
    ]


def scoped_desired(
    scope: Iterable[Mapping[str, Any]], legacy: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """범위 함수가 낸 묶음 서버와, 묶음이 없는 기존 서버 계약을 한 목록(이름 순)으로 합친다.

    묶음 서버는 범위에 닿을 때만 싣는다. 기존 서버는 범위 함수가 내지 않으므로 지금까지처럼 승인된
    것을 모두 싣되, 묶음 계약(``pack`` 있음)은 범위에 없으면 싣지 않는다.
    """
    items = {
        row["server_id"]: {
            "name": row["server_id"],
            "version": contract_version(row["exec_contract"]),
            "contract": row["exec_contract"],
            "pack_sha256": row["pack_sha256"],
            "permit_until": row["permit_until"].isoformat()
            if hasattr(row["permit_until"], "isoformat") else row["permit_until"],
        }
        for row in scope
    }
    plain = {n: d for n, d in legacy.items() if n not in items and not d.get("pack")}
    for item in desired_servers(plain):
        items[item["name"]] = item
    return [items[name] for name in sorted(items)][:MAX_DESIRED]


def revoke_names(
    statuses: Mapping[str, str], reported: Iterable[str], desired: Iterable[str]
) -> list[str]:
    """단말이 보고한 MINT 서버(등록된 승인 상태) 중 범위에 없는 이름."""
    keep = set(desired)
    return sorted(
        {n for n in reported if statuses.get(n) == "approved" and n not in keep}
    )[:MAX_DESIRED]


def merge_local_mcp(
    reported: Iterable[Mapping[str, Any]], previous: Iterable[Mapping[str, Any]] | None, now: str
) -> list[dict[str, Any]]:
    """보고한 항목에 처음 본 시각을 붙인다. 이전 보고에 같은 항목이 있으면 그 시각을 이어 받는다."""
    first = {
        (p["harness"], p["name"], p["target"], p.get("package")): p.get("first_seen")
        for p in previous or ()
        if isinstance(p, Mapping)
    }
    merged = []
    for item in reported:
        key = (item["harness"], item["name"], item["target"], item.get("package"))
        merged.append({**item, "first_seen": first.get(key) or now})
    return merged
