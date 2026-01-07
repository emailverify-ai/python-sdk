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
    BulkJobResponse,
    BulkResultItem,
    BulkResultsResponse,
    CreditsResponse,
    RateLimit,
    VerificationResult,
    VerificationStatus,
    VerifyResponse,
    Webhook,
    WebhookEvent,
)

__version__ = "1.0.0"

__all__ = [
    # Clients
    "EmailVerify",
    "AsyncEmailVerify",
    # Types
    "VerifyResponse",
    "VerificationResult",
    "VerificationStatus",
    "BulkJobResponse",
    "BulkResultItem",
    "BulkResultsResponse",
    "CreditsResponse",
    "RateLimit",
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
