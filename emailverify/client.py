"""EmailVerify SDK Client."""

import hashlib
import hmac
import time
from typing import Any, Dict, List, Optional

import httpx

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

DEFAULT_BASE_URL = "https://api.emailverify.ai/v1"
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3


class EmailVerify:
    """EmailVerify API Client."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        """Initialize the EmailVerify client.

        Args:
            api_key: Your EmailVerify API key.
            base_url: API base URL (default: https://api.emailverify.ai/v1).
            timeout: Request timeout in seconds (default: 30).
            retries: Number of retries for failed requests (default: 3).
        """
        if not api_key:
            raise AuthenticationError("API key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={
                "EMAILVERIFY-API-KEY": self.api_key,
                "Content-Type": "application/json",
                "User-Agent": "emailverify-python/1.0.0",
            },
        )

    def __enter__(self) -> "EmailVerify":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        attempt: int = 1,
    ) -> Any:
        """Make an HTTP request to the API."""
        try:
            response = self._client.request(
                method=method,
                url=path,
                json=json,
                params=params,
            )
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}")
        except httpx.RequestError as e:
            raise EmailVerifyError(f"Network error: {e}", "NETWORK_ERROR", 0)

        if response.status_code == 204:
            return None

        if response.is_success:
            return response.json()

        self._handle_error(response, method, path, json, params, attempt)

    def _handle_error(
        self,
        response: httpx.Response,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]],
        params: Optional[Dict[str, Any]],
        attempt: int,
    ) -> None:
        """Handle error responses."""
        try:
            data = response.json()
            error = data.get("error", {})
            message = error.get("message", response.reason_phrase)
            code = error.get("code", "UNKNOWN_ERROR")
            details = error.get("details")
        except Exception:
            message = response.reason_phrase
            code = "UNKNOWN_ERROR"
            details = None

        status = response.status_code

        if status == 401:
            raise AuthenticationError(message)

        if status == 403:
            if code == "INSUFFICIENT_CREDITS":
                raise InsufficientCreditsError(message)
            raise EmailVerifyError(message, code, status)

        if status == 404:
            raise NotFoundError(message)

        if status == 429:
            retry_after = int(response.headers.get("Retry-After", "0"))
            if attempt < self.retries:
                time.sleep(retry_after or (2**attempt))
                return self._request(method, path, json, params, attempt + 1)
            raise RateLimitError(message, retry_after)

        if status == 400:
            raise ValidationError(message, details)

        if status in (500, 502, 503):
            if attempt < self.retries:
                time.sleep(2**attempt)
                return self._request(method, path, json, params, attempt + 1)

        raise EmailVerifyError(message, code, status, details)

    def verify(
        self,
        email: str,
        smtp_check: bool = True,
        timeout: Optional[int] = None,
    ) -> VerifyResponse:
        """Verify a single email address.

        Args:
            email: The email address to verify.
            smtp_check: Whether to perform SMTP verification (default: True).
            timeout: Verification timeout in milliseconds.

        Returns:
            VerifyResponse with verification results.
        """
        payload: Dict[str, Any] = {"email": email, "smtp_check": smtp_check}
        if timeout is not None:
            payload["timeout"] = timeout

        data = self._request("POST", "/verify", json=payload)

        return VerifyResponse(
            email=data["email"],
            status=data["status"],
            result=VerificationResult(**data["result"]),
            score=data["score"],
            reason=data.get("reason"),
            credits_used=data["credits_used"],
        )

    def verify_bulk(
        self,
        emails: List[str],
        smtp_check: bool = True,
        webhook_url: Optional[str] = None,
    ) -> BulkJobResponse:
        """Submit a bulk verification job.

        Args:
            emails: List of email addresses to verify (max 10,000).
            smtp_check: Whether to perform SMTP verification (default: True).
            webhook_url: URL to receive completion notification.

        Returns:
            BulkJobResponse with job information.
        """
        if len(emails) > 10000:
            raise ValidationError("Maximum 10,000 emails per bulk job")

        payload: Dict[str, Any] = {"emails": emails, "smtp_check": smtp_check}
        if webhook_url:
            payload["webhook_url"] = webhook_url

        data = self._request("POST", "/verify/bulk", json=payload)

        return BulkJobResponse(
            job_id=data["job_id"],
            status=data["status"],
            total=data["total"],
            processed=data["processed"],
            valid=data["valid"],
            invalid=data["invalid"],
            unknown=data["unknown"],
            credits_used=data["credits_used"],
            created_at=data["created_at"],
            completed_at=data.get("completed_at"),
            progress_percent=data.get("progress_percent"),
        )

    def get_bulk_job_status(self, job_id: str) -> BulkJobResponse:
        """Get the status of a bulk verification job.

        Args:
            job_id: The bulk job ID.

        Returns:
            BulkJobResponse with current job status.
        """
        data = self._request("GET", f"/verify/bulk/{job_id}")

        return BulkJobResponse(
            job_id=data["job_id"],
            status=data["status"],
            total=data["total"],
            processed=data["processed"],
            valid=data["valid"],
            invalid=data["invalid"],
            unknown=data["unknown"],
            credits_used=data["credits_used"],
            created_at=data["created_at"],
            completed_at=data.get("completed_at"),
            progress_percent=data.get("progress_percent"),
        )

    def get_bulk_job_results(
        self,
        job_id: str,
        limit: int = 100,
        offset: int = 0,
        status: Optional[VerificationStatus] = None,
    ) -> BulkResultsResponse:
        """Get the results of a completed bulk verification job.

        Args:
            job_id: The bulk job ID.
            limit: Number of results per page (default: 100, max: 1000).
            offset: Starting position (default: 0).
            status: Filter by status ('valid', 'invalid', 'unknown').

        Returns:
            BulkResultsResponse with verification results.
        """
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status

        data = self._request("GET", f"/verify/bulk/{job_id}/results", params=params)

        results = [
            BulkResultItem(
                email=item["email"],
                status=item["status"],
                result=item["result"],
                score=item["score"],
            )
            for item in data["results"]
        ]

        return BulkResultsResponse(
            job_id=data["job_id"],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
            results=results,
        )

    def wait_for_bulk_job_completion(
        self,
        job_id: str,
        poll_interval: float = 5.0,
        max_wait: float = 600.0,
    ) -> BulkJobResponse:
        """Poll for bulk job completion.

        Args:
            job_id: The bulk job ID.
            poll_interval: Time between polls in seconds (default: 5).
            max_wait: Maximum wait time in seconds (default: 600).

        Returns:
            BulkJobResponse when job completes.

        Raises:
            TimeoutError: If job doesn't complete within max_wait.
        """
        start_time = time.time()

        while time.time() - start_time < max_wait:
            status = self.get_bulk_job_status(job_id)

            if status.status in ("completed", "failed"):
                return status

            time.sleep(poll_interval)

        raise TimeoutError(f"Bulk job {job_id} did not complete within {max_wait}s")

    def get_credits(self) -> CreditsResponse:
        """Get current credit balance.

        Returns:
            CreditsResponse with credit information.
        """
        data = self._request("GET", "/credits")

        return CreditsResponse(
            available=data["available"],
            used=data["used"],
            total=data["total"],
            plan=data["plan"],
            resets_at=data["resets_at"],
            rate_limit=RateLimit(
                requests_per_hour=data["rate_limit"]["requests_per_hour"],
                remaining=data["rate_limit"]["remaining"],
            ),
        )

    def create_webhook(
        self,
        url: str,
        events: List[WebhookEvent],
        secret: Optional[str] = None,
    ) -> Webhook:
        """Create a new webhook.

        Args:
            url: The webhook URL.
            events: List of events to subscribe to.
            secret: Optional webhook secret for signature verification.

        Returns:
            Webhook configuration.
        """
        payload: Dict[str, Any] = {"url": url, "events": events}
        if secret:
            payload["secret"] = secret

        data = self._request("POST", "/webhooks", json=payload)

        return Webhook(
            id=data["id"],
            url=data["url"],
            events=data["events"],
            created_at=data["created_at"],
        )

    def list_webhooks(self) -> List[Webhook]:
        """List all webhooks.

        Returns:
            List of Webhook configurations.
        """
        data = self._request("GET", "/webhooks")

        return [
            Webhook(
                id=item["id"],
                url=item["url"],
                events=item["events"],
                created_at=item["created_at"],
            )
            for item in data
        ]

    def delete_webhook(self, webhook_id: str) -> None:
        """Delete a webhook.

        Args:
            webhook_id: The webhook ID to delete.
        """
        self._request("DELETE", f"/webhooks/{webhook_id}")

    @staticmethod
    def verify_webhook_signature(
        payload: str,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify a webhook signature.

        Args:
            payload: The raw request body.
            signature: The signature from the request header.
            secret: Your webhook secret.

        Returns:
            True if signature is valid.
        """
        expected = f"sha256={hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()}"
        return hmac.compare_digest(signature, expected)


class AsyncEmailVerify:
    """Async EmailVerify API Client."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        """Initialize the async EmailVerify client."""
        if not api_key:
            raise AuthenticationError("API key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={
                "EMAILVERIFY-API-KEY": self.api_key,
                "Content-Type": "application/json",
                "User-Agent": "emailverify-python/1.0.0",
            },
        )

    async def __aenter__(self) -> "AsyncEmailVerify":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        attempt: int = 1,
    ) -> Any:
        """Make an async HTTP request to the API."""
        import asyncio

        try:
            response = await self._client.request(
                method=method,
                url=path,
                json=json,
                params=params,
            )
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}")
        except httpx.RequestError as e:
            raise EmailVerifyError(f"Network error: {e}", "NETWORK_ERROR", 0)

        if response.status_code == 204:
            return None

        if response.is_success:
            return response.json()

        await self._handle_error(response, method, path, json, params, attempt)

    async def _handle_error(
        self,
        response: httpx.Response,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]],
        params: Optional[Dict[str, Any]],
        attempt: int,
    ) -> None:
        """Handle error responses."""
        import asyncio

        try:
            data = response.json()
            error = data.get("error", {})
            message = error.get("message", response.reason_phrase)
            code = error.get("code", "UNKNOWN_ERROR")
            details = error.get("details")
        except Exception:
            message = response.reason_phrase
            code = "UNKNOWN_ERROR"
            details = None

        status = response.status_code

        if status == 401:
            raise AuthenticationError(message)

        if status == 403:
            if code == "INSUFFICIENT_CREDITS":
                raise InsufficientCreditsError(message)
            raise EmailVerifyError(message, code, status)

        if status == 404:
            raise NotFoundError(message)

        if status == 429:
            retry_after = int(response.headers.get("Retry-After", "0"))
            if attempt < self.retries:
                await asyncio.sleep(retry_after or (2**attempt))
                return await self._request(method, path, json, params, attempt + 1)
            raise RateLimitError(message, retry_after)

        if status == 400:
            raise ValidationError(message, details)

        if status in (500, 502, 503):
            if attempt < self.retries:
                await asyncio.sleep(2**attempt)
                return await self._request(method, path, json, params, attempt + 1)

        raise EmailVerifyError(message, code, status, details)

    async def verify(
        self,
        email: str,
        smtp_check: bool = True,
        timeout: Optional[int] = None,
    ) -> VerifyResponse:
        """Verify a single email address."""
        payload: Dict[str, Any] = {"email": email, "smtp_check": smtp_check}
        if timeout is not None:
            payload["timeout"] = timeout

        data = await self._request("POST", "/verify", json=payload)

        return VerifyResponse(
            email=data["email"],
            status=data["status"],
            result=VerificationResult(**data["result"]),
            score=data["score"],
            reason=data.get("reason"),
            credits_used=data["credits_used"],
        )

    async def verify_bulk(
        self,
        emails: List[str],
        smtp_check: bool = True,
        webhook_url: Optional[str] = None,
    ) -> BulkJobResponse:
        """Submit a bulk verification job."""
        if len(emails) > 10000:
            raise ValidationError("Maximum 10,000 emails per bulk job")

        payload: Dict[str, Any] = {"emails": emails, "smtp_check": smtp_check}
        if webhook_url:
            payload["webhook_url"] = webhook_url

        data = await self._request("POST", "/verify/bulk", json=payload)

        return BulkJobResponse(
            job_id=data["job_id"],
            status=data["status"],
            total=data["total"],
            processed=data["processed"],
            valid=data["valid"],
            invalid=data["invalid"],
            unknown=data["unknown"],
            credits_used=data["credits_used"],
            created_at=data["created_at"],
        )

    async def get_bulk_job_status(self, job_id: str) -> BulkJobResponse:
        """Get the status of a bulk verification job."""
        data = await self._request("GET", f"/verify/bulk/{job_id}")

        return BulkJobResponse(
            job_id=data["job_id"],
            status=data["status"],
            total=data["total"],
            processed=data["processed"],
            valid=data["valid"],
            invalid=data["invalid"],
            unknown=data["unknown"],
            credits_used=data["credits_used"],
            created_at=data["created_at"],
            completed_at=data.get("completed_at"),
            progress_percent=data.get("progress_percent"),
        )

    async def get_bulk_job_results(
        self,
        job_id: str,
        limit: int = 100,
        offset: int = 0,
        status: Optional[VerificationStatus] = None,
    ) -> BulkResultsResponse:
        """Get the results of a completed bulk verification job."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status

        data = await self._request(
            "GET", f"/verify/bulk/{job_id}/results", params=params
        )

        results = [
            BulkResultItem(
                email=item["email"],
                status=item["status"],
                result=item["result"],
                score=item["score"],
            )
            for item in data["results"]
        ]

        return BulkResultsResponse(
            job_id=data["job_id"],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
            results=results,
        )

    async def wait_for_bulk_job_completion(
        self,
        job_id: str,
        poll_interval: float = 5.0,
        max_wait: float = 600.0,
    ) -> BulkJobResponse:
        """Poll for bulk job completion."""
        import asyncio

        start_time = time.time()

        while time.time() - start_time < max_wait:
            status = await self.get_bulk_job_status(job_id)

            if status.status in ("completed", "failed"):
                return status

            await asyncio.sleep(poll_interval)

        raise TimeoutError(f"Bulk job {job_id} did not complete within {max_wait}s")

    async def get_credits(self) -> CreditsResponse:
        """Get current credit balance."""
        data = await self._request("GET", "/credits")

        return CreditsResponse(
            available=data["available"],
            used=data["used"],
            total=data["total"],
            plan=data["plan"],
            resets_at=data["resets_at"],
            rate_limit=RateLimit(
                requests_per_hour=data["rate_limit"]["requests_per_hour"],
                remaining=data["rate_limit"]["remaining"],
            ),
        )

    async def create_webhook(
        self,
        url: str,
        events: List[WebhookEvent],
        secret: Optional[str] = None,
    ) -> Webhook:
        """Create a new webhook."""
        payload: Dict[str, Any] = {"url": url, "events": events}
        if secret:
            payload["secret"] = secret

        data = await self._request("POST", "/webhooks", json=payload)

        return Webhook(
            id=data["id"],
            url=data["url"],
            events=data["events"],
            created_at=data["created_at"],
        )

    async def list_webhooks(self) -> List[Webhook]:
        """List all webhooks."""
        data = await self._request("GET", "/webhooks")

        return [
            Webhook(
                id=item["id"],
                url=item["url"],
                events=item["events"],
                created_at=item["created_at"],
            )
            for item in data
        ]

    async def delete_webhook(self, webhook_id: str) -> None:
        """Delete a webhook."""
        await self._request("DELETE", f"/webhooks/{webhook_id}")

    @staticmethod
    def verify_webhook_signature(
        payload: str,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify a webhook signature."""
        expected = f"sha256={hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()}"
        return hmac.compare_digest(signature, expected)
