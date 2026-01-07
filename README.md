# emailverify

Official EmailVerify Python SDK for email verification.

**Documentation:** https://emailverify.ai/docs

## Installation

```bash
pip install emailverify-ai
```

## Quick Start

```python
from emailverify import EmailVerify

client = EmailVerify(api_key="your-api-key")

# Verify a single email
result = client.verify("user@example.com")
print(result.status)  # 'valid', 'invalid', 'unknown', or 'accept_all'
```

## Configuration

```python
client = EmailVerify(
    api_key="your-api-key",        # Required
    base_url="https://api.emailverify.ai/v1",  # Optional
    timeout=30.0,                   # Optional: Request timeout in seconds (default: 30)
    retries=3,                      # Optional: Number of retries (default: 3)
)
```

## Single Email Verification

```python
result = client.verify(
    email="user@example.com",
    smtp_check=True,  # Optional: Perform SMTP verification (default: True)
    timeout=5000,     # Optional: Verification timeout in ms
)

print(result.email)           # 'user@example.com'
print(result.status)          # 'valid'
print(result.score)           # 0.95
print(result.result.deliverable)  # True
print(result.result.disposable)   # False
```

## Bulk Email Verification

```python
# Submit a bulk verification job
job = client.verify_bulk(
    emails=["user1@example.com", "user2@example.com", "user3@example.com"],
    smtp_check=True,
    webhook_url="https://your-app.com/webhooks/emailverify",  # Optional
)

print(job.job_id)  # 'job_abc123xyz'

# Check job status
status = client.get_bulk_job_status(job.job_id)
print(status.progress_percent)  # 45

# Wait for completion (polling)
completed = client.wait_for_bulk_job_completion(
    job_id=job.job_id,
    poll_interval=5.0,  # seconds
    max_wait=600.0,     # seconds
)

# Get results
results = client.get_bulk_job_results(
    job_id=job.job_id,
    limit=100,
    offset=0,
    status="valid",  # Optional: filter by status
)

for item in results.results:
    print(f"{item.email}: {item.status}")
```

## Async Support

```python
import asyncio
from emailverify import AsyncEmailVerify

async def main():
    async with AsyncEmailVerify(api_key="your-api-key") as client:
        result = await client.verify("user@example.com")
        print(result.status)

asyncio.run(main())
```

## Credits

```python
credits = client.get_credits()
print(credits.available)  # 9500
print(credits.plan)       # 'Professional'
print(credits.rate_limit.remaining)  # 9850
```

## Webhooks

```python
# Create a webhook
webhook = client.create_webhook(
    url="https://your-app.com/webhooks/emailverify",
    events=["verification.completed", "bulk.completed"],
    secret="your-webhook-secret",
)

# List webhooks
webhooks = client.list_webhooks()

# Delete a webhook
client.delete_webhook(webhook.id)

# Verify webhook signature
from emailverify import EmailVerify

is_valid = EmailVerify.verify_webhook_signature(
    payload=raw_body,
    signature=signature_header,
    secret="your-webhook-secret",
)
```

## Error Handling

```python
from emailverify import (
    EmailVerify,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    InsufficientCreditsError,
    NotFoundError,
    TimeoutError,
)

try:
    result = client.verify("user@example.com")
except AuthenticationError:
    print("Invalid API key")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
except ValidationError as e:
    print(f"Invalid input: {e.message}")
except InsufficientCreditsError:
    print("Not enough credits")
except TimeoutError:
    print("Request timed out")
```

## Context Manager

```python
with EmailVerify(api_key="your-api-key") as client:
    result = client.verify("user@example.com")
    print(result.status)
# Connection is automatically closed
```

## Type Hints

This SDK includes full type annotations for IDE support and type checking.

```python
from emailverify import VerifyResponse, BulkJobResponse, CreditsResponse

def process_result(result: VerifyResponse) -> None:
    if result.status == "valid":
        print(f"Email {result.email} is valid")
```

## License

MIT
