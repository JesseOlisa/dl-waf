from fastapi import APIRouter, Depends, Query

from backend import database
from backend.routes.deps import get_current_user
from backend.schemas import AttackStat, SummaryStats, TrafficPoint

router = APIRouter()


@router.get("/summary", response_model=SummaryStats)
def summary_stats(_: str = Depends(get_current_user)):
    return database.get_summary_stats()


@router.get("/traffic", response_model=list[TrafficPoint])
def traffic_series(
    hours: int = Query(default=24, ge=1, le=720),
    _: str = Depends(get_current_user),
):
    return database.get_traffic_series(hours)


@router.get("/attacks", response_model=list[AttackStat])
def attack_breakdown(_: str = Depends(get_current_user)):
    return database.get_attack_breakdown()
