"""WAF kill-switch — read/toggle the runtime protection state + audit trail."""

import logging

from fastapi import APIRouter, Depends, Query

from backend import database
from backend.routes.deps import get_current_user
from backend.schemas import WafAuditItem, WafStatus, WafToggleRequest

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", response_model=WafStatus)
def waf_status(_: str = Depends(get_current_user)):
    return database.get_waf_status()


@router.post("/toggle", response_model=WafStatus)
def toggle_waf(body: WafToggleRequest, actor: str = Depends(get_current_user)):
    logger.warning(
        "WAF %s by %s", "ENABLED" if body.enabled else "DISABLED", actor
    )
    database.set_waf_enabled(actor, body.enabled, body.note)
    # Invalidate the middleware's cached flag so the change takes effect immediately.
    from backend.middleware import invalidate_waf_cache

    invalidate_waf_cache()
    return database.get_waf_status()


@router.get("/audit", response_model=list[WafAuditItem])
def waf_audit(
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user),
):
    return database.get_waf_audit(limit)
