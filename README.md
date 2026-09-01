# Authorized Scan Orchestrator

FastAPI service for scheduling **authorized** security testing jobs. It deliberately accepts fixed profiles only and contains no endpoint for arbitrary scanner or shell commands.

## Current scope

- Configurable authentication: OIDC bearer tokens in production, temporary API keys locally
- Authorization reference recorded for every target
- Idempotent job submission and cancellation
- Durable PostgreSQL/SQLite job model
- A worker boundary that will later dispatch signed, fixed-profile jobs to a private controller

The controller integration is intentionally unimplemented. Do not add shell execution to the API or worker.

## Authentication and rate limits

Production starts only when `AUTH_MODE=oidc`, OIDC issuer/audience/JWKS settings, and a Redis-compatible rate-limit URL are configured. Tokens must include a `sub` plus an `operator` or `admin` value in the configurable `roles` claim. Administrators register targets and view audit events; operators queue and cancel scans.

API-key mode is intentionally restricted to non-production environments. Redis rate limits requests by authenticated subject; the service fails closed if the rate limiter is unavailable in production.

## Result handling and retention

Raw controller output is never returned by the API. The private worker encrypts it with `RESULT_ENCRYPTION_KEY`, stores the ciphertext in an S3-compatible bucket, optionally requests provider KMS encryption, and records only the checksum, byte count, expiry, and deletion tombstone in Postgres. The API serves normalized result summaries and artifact metadata. The worker purges expired objects hourly; configure a matching object-storage lifecycle policy as defense in depth.

## Controller protocol

The controller initiates all communication by polling the hidden `/v1/internal/controller/` routes over HTTPS. Each request includes a timestamp, unique nonce, SHA-256 body hash, and HMAC-SHA256 signature derived from `CONTROLLER_SHARED_SECRET`; nonces are stored to reject replays. The controller can claim a queued fixed-profile job, report a normalized completion, or mark the job failed. [controller_agent.py](controller_agent.py) is a transport template only—it must not be extended with user-supplied scanner arguments.

## Local development

1. Create and activate a Python 3.12 virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and replace development secrets.
4. Apply the schema: `alembic upgrade head`
5. Run: `uvicorn app.main:app --reload`
6. Test: `pytest`

API docs are available at `http://localhost:8000/docs`.

## Deployment order

1. Deploy this API and worker to staging with managed Postgres.
2. Apply migrations using `alembic upgrade head`; production does not auto-create tables.
3. Replace temporary API-key roles with OIDC, then add RBAC, rate limits, object storage, monitoring, and alerts.
4. Provision a separate locked-down controller VPS and verify Axiom/Ax manually against an authorized test target.
5. Add a signed private controller protocol for the two allowed profiles; validate controller responses and ensure fleet cleanup.
6. Perform a security review and constrained production pilot.

## Important constraints

- Only scan assets for which you have documented authorization.
- Never send cloud credentials, controller SSH keys, or Axiom configuration through this API.
- Store raw scan artifacts in encrypted object storage; store only metadata and references in Postgres.
