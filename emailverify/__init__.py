"""EmailVerify Python SDK for email verification."""

from .client import AsyncEmailVerify, EmailVerify
from .exceptions import (
    AuthenticationError,
    EmailVerifyError,
    InsufficientCreditsError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    ValidationError,
)
from .types import (
    BulkVerificationResult,
    BulkVerifyResponse,
    CreditsResponse,
    DomainReputation,
    FileJobResponse,
    FileResultItem,
    FileResultsResponse,
    HealthCheckResponse,
    JobStatus,
    VerificationResult,
    VerificationStatus,
    Webhook,
    WebhookEvent,
)

__version__ = "1.0.0"

__all__ = [
    # Clients
    "EmailVerify",
    "AsyncEmailVerify",
    # Types
    "VerificationResult",
    "VerificationStatus",
    "BulkVerificationResult",
    "BulkVerifyResponse",
    "FileJobResponse",
    "FileResultItem",
    "FileResultsResponse",
    "CreditsResponse",
    "HealthCheckResponse",
    "DomainReputation",
    "JobStatus",
    "Webhook",
    "WebhookEvent",
    # Exceptions
    "EmailVerifyError",
    "AuthenticationError",
    "RateLimitError",
    "ValidationError",
    "InsufficientCreditsError",
    "NotFoundError",
    "TimeoutError",
]
