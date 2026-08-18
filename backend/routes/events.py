import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend import database
from backend.routes.deps import get_current_user
from backend.schemas import EventOut, EventsResponse

router = APIRouter()


@router.get("", response_model=EventsResponse)
def list_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    classification: Optional[int] = Query(default=None),
    attack_type: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user),
):
    items, total = database.get_events(
        page=page,
        page_size=page_size,
        classification=classification,
        attack_type=attack_type,
        start_time=start_time,
        end_time=end_time,
        source_ip=source_ip,
    )
    return EventsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, _: str = Depends(get_current_user)):
    event = database.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
