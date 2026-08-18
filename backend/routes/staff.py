"""
Staff workstation API — the bank's internal back-office surface.

These endpoints are intentionally UNAUTHENTICATED to the SOC: they represent a
staff member's ordinary traffic, which the WAF inspects the same way it would
any request. The events they generate flow into the same database the SOC
dashboard monitors. The WAF on/off state is the shared kill-switch the SOC
controls, so toggling protection in the SOC immediately changes what happens here.
"""

import logging

from fastapi import APIRouter, HTTPException

from backend import database
from backend.schemas import (
    RunResult,
    StaffFieldSpec,
    StaffRunRequest,
    StaffTaskOut,
    StaffVariantMeta,
    WafStatus,
)
from backend.simulation import bank_db, runner
from backend.simulation.staff_tasks import STAFF_SOURCE_IP, TASKS, get_variant

logger = logging.getLogger(__name__)

router = APIRouter()

_STAFF_ACTOR = "staff:amaka.eze"


def _variant_meta(task: dict, v: dict) -> StaffVariantMeta:
    risky_field = next((f["name"] for f in task["fields"] if f.get("risky")), None)
    highlight = v["fields"].get(risky_field) if risky_field else None
    return StaffVariantMeta(
        id=v["id"],
        variant_id=v["variant_id"],
        kind=v["kind"],
        label=v["label"],
        category=v["category"],
        title=v["title"],
        fields=v["fields"],
        highlight=highlight,
    )


@router.get("/protection", response_model=WafStatus)
def protection_status():
    """Open — lets the staff portal show whether the SOC has protection on."""
    return database.get_waf_status()


@router.get("/tasks", response_model=list[StaffTaskOut])
def list_tasks():
    return [
        StaffTaskOut(
            id=t["id"],
            title=t["title"],
            icon=t["icon"],
            blurb=t["blurb"],
            fields=[StaffFieldSpec(**f) for f in t["fields"]],
            variants=[_variant_meta(t, v) for v in t["variants"]],
        )
        for t in TASKS
    ]


@router.post("/run", response_model=RunResult)
def run(body: StaffRunRequest):
    variant = get_variant(body.variant_id)
    if variant is None:
        raise HTTPException(status_code=404, detail="Unknown task variant")
    bank_db.ensure_seeded()
    waf_enabled = database.get_waf_enabled()
    result = runner.run_scenario(
        variant, waf_enabled, actor=_STAFF_ACTOR, source_ip=STAFF_SOURCE_IP
    )
    logger.info(
        "[STAFF] %s waf=%s verdict=%s outcome=%s model=%.3f sig=%s",
        variant["id"],
        "ON" if waf_enabled else "OFF",
        result["verdict"],
        result["outcome"],
        result["model"]["confidence"],
        result["signature"]["matched"],
    )
    return result
