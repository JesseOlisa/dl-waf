from typing import Optional
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EventOut(BaseModel):
    event_id: int
    timestamp: str
    source_ip: Optional[str]
    http_method: Optional[str]
    request_uri: Optional[str]
    classification: int
    confidence_score: float
    attack_type: Optional[str]
    action_taken: str
    payload_fragment: Optional[str]
    scenario_id: Optional[str] = None
    latency_ms: Optional[float] = None
    waf_enabled: Optional[int] = None


class EventsResponse(BaseModel):
    items: list[EventOut]
    total: int
    page: int
    page_size: int
    pages: int


class SummaryStats(BaseModel):
    total_requests: int
    blocked: int
    allowed: int
    attacks_succeeded: int = 0
    detection_rate: float


class TrafficPoint(BaseModel):
    timestamp: str
    legitimate: int
    malicious: int


class AttackStat(BaseModel):
    attack_type: str
    count: int


# ── WAF kill-switch ────────────────────────────────────────────────────────────

class WafStatus(BaseModel):
    enabled: bool
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None


class WafToggleRequest(BaseModel):
    enabled: bool
    note: Optional[str] = None


class WafAuditItem(BaseModel):
    id: int
    timestamp: str
    actor: str
    action: str
    note: Optional[str] = None


# ── Attack simulation ──────────────────────────────────────────────────────────

class ScenarioOut(BaseModel):
    id: str
    category: str            # "SQL Injection" | "XSS" | "Legitimate"
    title: str
    level: int               # escalation level (0 for baseline)
    description: str
    method: str
    target_uri: str
    payload: str
    param_name: str
    expected_classification: int   # 1 = should be blocked, 0 = benign
    expected_evades: bool = False


class ModelVerdict(BaseModel):
    label: int
    confidence: float
    threshold: float


class SignatureVerdict(BaseModel):
    matched: bool
    category: Optional[str] = None
    pattern: Optional[str] = None


class Consequence(BaseModel):
    kind: str                # "rows" | "cookie" | "defacement" | "boolean_leak" | "none"
    title: str
    summary: Optional[str] = None
    columns: Optional[list[str]] = None
    rows: Optional[list[list]] = None
    cookie: Optional[str] = None
    defaced_html: Optional[str] = None
    detail: Optional[str] = None


class RunRequest(BaseModel):
    scenario_id: str


class CampaignRequest(BaseModel):
    include_baseline: bool = True


class RunResult(BaseModel):
    scenario_id: str
    category: str
    title: str
    level: int
    waf_enabled: bool
    raw_request: str
    model: ModelVerdict
    signature: SignatureVerdict
    final_label: int
    blocked_by: Optional[str] = None    # "model" | "signature" | "both" | None
    latency_ms: float
    verdict: str                        # "BLOCKED" | "ALLOWED"
    outcome: str                        # "attack_blocked" | "attack_succeeded" | "legitimate_allowed"
    event_id: int
    consequence: Optional[Consequence] = None


class CampaignSummary(BaseModel):
    total: int
    blocked: int
    succeeded: int
    legitimate_allowed: int


class CampaignResult(BaseModel):
    results: list[RunResult]
    summary: CampaignSummary


class ResetResult(BaseModel):
    status: str
    seeded_at: str


# ── Staff workstation ──────────────────────────────────────────────────────────

class StaffFieldSpec(BaseModel):
    name: str
    label: str
    type: str = "text"
    risky: bool = False


class StaffVariantMeta(BaseModel):
    id: str
    variant_id: str
    kind: str                # "legitimate" | "malicious"
    label: str
    category: str
    title: str
    fields: dict
    highlight: Optional[str] = None


class StaffTaskOut(BaseModel):
    id: str
    title: str
    icon: str
    blurb: str
    fields: list[StaffFieldSpec]
    variants: list[StaffVariantMeta]


class StaffRunRequest(BaseModel):
    variant_id: str
