"""Attack simulation console API — list, fire, campaign, and reset scenarios."""

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend import database
from backend.routes.deps import get_current_user
from backend.schemas import (
    CampaignRequest,
    CampaignResult,
    CampaignSummary,
    ResetResult,
    RunRequest,
    RunResult,
    ScenarioOut,
)
from backend.simulation import bank_db, runner
from backend.simulation.scenarios import SCENARIOS, get_scenario

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/scenarios", response_model=list[ScenarioOut])
def list_scenarios(_: str = Depends(get_current_user)):
    return SCENARIOS


def _log_run(result: dict) -> None:
    logger.info(
        "[SIM] scenario=%s waf=%s verdict=%s outcome=%s model=%.3f signature=%s blocked_by=%s latency=%sms uri=%s",
        result["scenario_id"],
        "ON" if result["waf_enabled"] else "OFF",
        result["verdict"],
        result["outcome"],
        result["model"]["confidence"],
        result["signature"]["matched"],
        result["blocked_by"],
        result["latency_ms"],
        result["raw_request"].splitlines()[0] if result["raw_request"] else "",
    )


@router.post("/run", response_model=RunResult)
def run(body: RunRequest, actor: str = Depends(get_current_user)):
    scenario = get_scenario(body.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    bank_db.ensure_seeded()
    waf_enabled = database.get_waf_enabled()
    result = runner.run_scenario(scenario, waf_enabled, actor)
    _log_run(result)
    return result


@router.post("/campaign", response_model=CampaignResult)
def campaign(body: CampaignRequest, actor: str = Depends(get_current_user)):
    bank_db.ensure_seeded()
    waf_enabled = database.get_waf_enabled()

    results = []
    for scenario in SCENARIOS:
        if scenario["category"] == "Legitimate" and not body.include_baseline:
            continue
        results.append(runner.run_scenario(scenario, waf_enabled, actor))

    blocked = sum(1 for r in results if r["outcome"] == "attack_blocked")
    succeeded = sum(1 for r in results if r["outcome"] == "attack_succeeded")
    legit = sum(1 for r in results if r["outcome"] == "legitimate_allowed")
    summary = CampaignSummary(
        total=len(results), blocked=blocked, succeeded=succeeded, legitimate_allowed=legit
    )
    return CampaignResult(results=results, summary=summary)


@router.post("/reset", response_model=ResetResult)
def reset(actor: str = Depends(get_current_user)):
    seeded_at = bank_db.reset()
    database.add_waf_audit(actor, "SIM_RESET", "Vulnerable bank database re-seeded")
    logger.info("Simulation bank DB reset by %s", actor)
    return ResetResult(status="reset", seeded_at=seeded_at)
