"""감사 보고서 화면과 API. 읽기 전용이며 운영자 역할(관리자·승인자·조회자) 모두가 본다."""

from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from mint_litellm.console import audit_report, setup_state
from mint_litellm.console.core import Actor, api_actor, page_actor, public, require_csrf
from mint_litellm.console.templating import render

router = APIRouter(dependencies=[Depends(require_csrf)])
api_router = APIRouter(dependencies=[Depends(require_csrf)])


def make(actor: Actor, range_name, since, until) -> dict:
    zone = actor.config.zone
    start, end = audit_report.resolve_period(zone, range_name, since, until)
    root = actor.config.policy_source.root if actor.config.policy_source else None
    return audit_report.build(
        actor.conn, actor.instance, start, end, zone=zone, catalog=audit_report.load_catalog(root)
    )


@router.get("/reports/audit")
def audit_page(
    request: Request,
    range: str | None = None,
    since: str | None = None,
    until: str | None = None,
    actor: Actor = Depends(page_actor),
):
    report = make(actor, range, since, until)
    setup_state.mark(actor.conn, actor.instance, "audit_report", actor.ctx.operator.name)
    meta = report["meta"]
    current = "" if since or until else range or audit_report.DEFAULT_RANGE
    export = urlencode({"from": meta["from"], "to": meta["to"]})
    ctx = {
        "report": report,
        "choices": [
            (text, f"/reports/audit?range={value}", value == current)
            for value, text, _ in audit_report.RANGES
        ],
        "since": meta["from"],
        "until": meta["to"],
        "zip_href": f"/api/v1/reports/audit?{export}&format=zip",
    }
    return render(request, "audit_report.html", ctx, actor=actor)


@api_router.get("/reports/audit")
def audit_api(
    format: Literal["json", "zip"] = "json",
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    actor: Actor = Depends(api_actor),
):
    report = make(actor, None, from_, to)
    if format == "zip":
        meta = report["meta"]
        name = f"audit-{meta['from']}_{meta['to']}.zip"
        return Response(
            audit_report.to_zip(report),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )
    return public(report)
