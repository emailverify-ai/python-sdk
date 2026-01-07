"""EmailVerify SDK Types."""

from dataclasses import dataclass
from typing import List, Literal, Optional


VerificationStatus = Literal["valid", "invalid", "unknown", "accept_all"]
JobStatus = Literal["pending", "processing", "completed", "failed"]
WebhookEvent = Literal[
    "verification.completed", "bulk.completed", "bulk.failed", "credits.low"
]


@dataclass
class VerificationResult:
    """Detailed verification result."""

    deliverable: bool
    valid_format: bool
    valid_domain: bool
    valid_mx: bool
    disposable: bool
    role: bool
    catchall: bool
    free: bool
    smtp_valid: bool


@dataclass
class VerifyResponse:
    """Response from single email verification."""

    email: str
    status: VerificationStatus
    result: VerificationResult
    score: float
    reason: Optional[str]
    credits_used: int


@dataclass
class BulkJobResponse:
    """Response from bulk verification job."""

    job_id: str
    status: JobStatus
    total: int
    processed: int
    valid: int
    invalid: int
    unknown: int
    credits_used: int
    created_at: str
    completed_at: Optional[str] = None
    progress_percent: Optional[int] = None


@dataclass
class BulkResultItem:
    """Single result item from bulk verification."""

    email: str
    status: VerificationStatus
    result: dict
    score: float


@dataclass
class BulkResultsResponse:
    """Response from bulk job results."""

    job_id: str
    total: int
    limit: int
    offset: int
    results: List[BulkResultItem]


@dataclass
class RateLimit:
    """Rate limit information."""

    requests_per_hour: int
    remaining: int


@dataclass
class CreditsResponse:
    """Response from credits endpoint."""

    available: int
    used: int
    total: int
    plan: str
    resets_at: str
    rate_limit: RateLimit


@dataclass
class Webhook:
    """Webhook configuration."""

    id: str
    url: str
    events: List[WebhookEvent]
    created_at: str
