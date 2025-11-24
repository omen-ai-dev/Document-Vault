# Document Vault Service

## Overview

Document Vault is a FastAPI service that stores and manages legal or compliance documents.  
It focuses on four core responsibilities:

- **Document lifecycle** – upload, verify, list, relink, and archive documents persisted in Postgres.
- **Secure storage** – files are pushed to S3 with KMS encryption, SHA-256 hashing, and duplicate detection.
- **Event emission** – downstream systems receive document lifecycle events through SQS and audit events through SNS.
- **Integrity signalling** – hash mismatches raise compliance alerts and mark the document as `mismatch`.

The application also ships with an asynchronous consumer that listens for entity deletion events and cascades soft-archival of related documents.

---

## Architecture at a Glance

| Concern      | Implementation |
|--------------|----------------|
| API          | FastAPI + Pydantic v2, routers in `app/api` |
| Persistence  | SQLAlchemy (async) models for `documents` and `processed_events`, default Postgres connection |
| Storage      | `StorageService` uploads to S3 using SSE-KMS and issues presigned download URLs |
| Hashing      | `HashingService` computes SHA-256 digests for upload & verification flows |
| Access       | Authorization checks delegated to EPR service (HTTP client) or a mock RBAC implementation |
| Events       | `DocumentEventPublisher` (SQS) and `AuditEventPublisher` (API) publish document lifecycle events |
| Blockchain   | `BlockchainService` is currently a mock that logs registrations |
| Background   | `DocumentVaultConsumer` polls SQS for entity deletion events and invokes cascade archival |

---

## Repository Layout

```
app/
  api/          FastAPI dependencies and document routes
  core/         Settings and logging configuration
  db/           Async SQLAlchemy session factory
  events/       SQS publishers (document + integrity alerts)
  models/       SQLAlchemy models (Document, ProcessedEvent)
  schemas/      Pydantic request/response models
  services/     Domain services (document, storage, hashing, access, blockchain, audit)
  workers/      Background consumer for entity deletion events
infra/          ECS task definition template
tests/          Pytest suite (mixed async + sync tests with mocks)
```

Supporting docs live at the repo root (`Document Vault Overview.md`, `CONSUMER_IMPLEMENTATION.md`).

---

## API Surface

All endpoints are mounted under `/api/v1/documents` unless noted otherwise.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/upload` | Multipart upload for a document; commits metadata + S3 object, emits events |
| `POST` | `/verify` | Re-hashes S3 object, updates status (`verified`/`mismatch`), emits events and alerts |
| `GET`  | `/{entity_id}` | Lists non-archived documents for an entity (archived entries currently excluded) |
| `GET`  | `/{document_id}/download` | Returns a presigned URL for download |
| `POST` | `/{document_id}/relink` | Moves a document to a new entity + optional token id |
| `DELETE` | `/{document_id}` | Soft deletes (archives) the document |
| `POST` | `/{document_id}/signatures/request` | Initiates a DocuSign signature workflow for the provided stakeholders |
| `GET`  | `/{document_id}/signatures/status` | Returns the document plus aggregated signature progress |
| `POST` | `/signatures/webhook/docusign` | DocuSign Connect webhook endpoint (JSON) used to reconcile signer status |
| `GET` | `/healthz` | Simple readiness probe |

Responses are defined in `app/schemas/document.py`. Upload requests expect `metadata` as JSON (optional) alongside form fields.

---

## Core Components

- **`DocumentService`** orchestrates authorization, validation, hashing, storage, event publication, and DB writes.
- **`StorageService`** wraps aioboto3 for S3 interactions (uploads, streaming, presigned URL generation).
- **`AuditEventPublisher`** sends lifecycle audit events to the EPR service API.
- **`DocumentEventPublisher`** emits document lifecycle events and (if configured) integrity alerts to SQS.
- **`HashingService`** streams SHA-256 hashing with configurable buffer size.
- **`EprService` / `EprServiceMock`** encapsulate permission checks against the Entity & Permissions (EPR) service.
- **`DocumentVaultConsumer`** processes `entity.deleted` events, archives related documents, and records processed message IDs for deduplication.

---

## Events & Integrations

- **Document lifecycle events** (`document.uploaded`, `document.verified`, `document.mismatch`, `document.archived`, `document.relinked`) are published via SQS.
- **Signature events** (`document.signature_requested`, `document.signature_completed`) are emitted whenever envelopes are created and when all recipients finish signing.
- **Audit events** for the same actions are pushed to the EPR service API for centralised ledgering.
- **Integrity alerts** on hash mismatch are optionally emitted to a compliance alert queue with severity metadata.
- **Blockchain integration** is currently stubbed; `register_document` logs and returns a deterministic fake tx id.

---

## Configuration

Configuration is driven by environment variables parsed in `app/core/config.py`. Key settings:

### Application & API
- `ENVIRONMENT` (`local`, `dev`, `staging`, `prod`, `test`)
- `API_V1_PREFIX` (default `/api/v1`)

### Database
- `DATABASE_URL` (SQLAlchemy async URL, e.g. `postgresql+psycopg://...`)
- `DATABASE_POOL_SIZE`, `DATABASE_MAX_OVERFLOW`, `DATABASE_POOL_PRE_PING`

### AWS / Storage
- `AWS_REGION`, `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- `DOCUMENT_VAULT_BUCKET`
- `AWS_S3_KMS_KEY_ID`
- `AWS_S3_ENDPOINT_URL` (optional override for LocalStack)
- `MAX_UPLOAD_FILE_SIZE_BYTES` (default 100 MiB)
- `ALLOWED_MIME_TYPES` (list, default covers PDF, Office docs, text, common images)
- `ENABLE_DUPLICATE_HASH_DETECTION` (bool)
- `PRESIGNED_URL_EXPIRATION_SECONDS` (int, see caveat below)

### Messaging & Events
- `DOCUMENT_EVENTS_QUEUE_URL`
- `COMPLIANCE_ALERT_QUEUE_URL` (optional)

### Access Control
- `EPR_MOCK_MODE` (`true` grants everything, `false` uses HTTP client)
- `EPR_SERVICE_URL`, `EPR_SERVICE_TIMEOUT`
- `USER_DIRECTORY_BASE_URL`, `USER_DIRECTORY_API_KEY` (optional bearer token)

### DocuSign
- `DOCUSIGN_BASE_PATH`, `DOCUSIGN_OAUTH_BASE_PATH`
- `DOCUSIGN_ACCOUNT_ID`
- `DOCUSIGN_INTEGRATION_KEY`
- `DOCUSIGN_USER_ID`
- `DOCUSIGN_PRIVATE_KEY` (PEM contents)
- `DOCUSIGN_WEBHOOK_SECRET` (optional shared secret for Connect notifications)

### Blockchain
- `BLOCKCHAIN_ENDPOINT_URL` (reserved for future real integration)

### Logging
- `LOG_LEVEL` (`INFO` default)
- `LOG_FORMAT` (`json` or `text`)

### Consumer
- `ENABLE_DOCUMENT_CONSUMER`
- `DOCUMENT_VAULT_SQS_URL`
- `DOCUMENT_CONSUMER_MAX_MESSAGES`
- `DOCUMENT_CONSUMER_WAIT_TIME`
- `DOCUMENT_CONSUMER_VISIBILITY_TIMEOUT` (optional)

> **Important:** `Settings` currently defines `presigned_url_expiration_seconds` twice. The second definition (without aliases) overrides the first, so environment overrides are ignored and the value defaults to `3600`. See Known Limitations for details.

---

## Local Development

1. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
2. **Configure environment**
   ```bash
   cp .env.example .env
   # populate DATABASE_URL, AWS credentials (or set ENABLE_DOCUMENT_CONSUMER=false), queues, etc.
   ```
   For ad-hoc development you can target SQLite: `DATABASE_URL=sqlite+aiosqlite:///./document_vault.db`.

3. **Run the API**
   ```bash
   uvicorn app.main:app --reload
   ```

4. **Run tests**
   ```bash
   pytest -vv
   ```
   The suite currently defines 112 tests across nine modules. Tests rely heavily on mocks; no AWS calls are made.

---

## Database Schema

### `documents`
| Column | Notes |
|--------|-------|
| `id` (UUID PK) | Generated UUID |
| `entity_type` | Enum (`issuer`, `investor`, `deal`, `token`, `compliance`) |
| `entity_id` | UUID of owning entity |
| `token_id` | Optional int |
| `document_type` | Enum (operating agreement, KYC, etc.) |
| `filename`, `mime_type`, `size_bytes` | Original file metadata |
| `storage_bucket`, `storage_key`, `storage_version_id` | S3 placement |
| `sha256_hash` | Indexed |
| `hash_verified_at`, `on_chain_reference` | Verification metadata |
| `status` | Enum (`uploaded`, `verified`, `mismatch`, `archived`) |
| `uploaded_by`, `verified_by`, `archived_by` | UUID actors |
| `archived_at` | Timestamp for soft delete |
| `metadata` | JSON payload (optional) |
| `signatures` | JSON array of signer metadata (DocuSign envelope recipients) |
| `signature_state` | Enum (`not_requested`, `pending`, `partial`, `completed`) |
| `signature_envelope_id` | DocuSign envelope identifier |
| `created_at`, `updated_at` | Auto timestamps |

### `document_vault_processed_events`
| Column | Notes |
|--------|-------|
| `id` (UUID PK) | Generated UUID |
| `event_id` | Unique identifier for deduplication |
| `source`, `action` | Event metadata |
| `entity_id`, `entity_type` | Optional origin metadata |
| `created_at`, `updated_at` | Auto timestamps |

---

## Background Consumer

`app.workers.document_vault_consumer.DocumentVaultConsumer` continuously polls an SQS queue (long-polling by default) for `entity.deleted` events. Each message:

1. Validates payload (supports SNS envelope or direct SQS payloads).
2. Skips already processed events using the `document_vault_processed_events` table.
3. Invokes `DocumentService.cascade_archive_by_entity`, which archives any non-archived documents for that entity and emits audit/document events.
4. Deletes the message upon success.

Lifecycle is managed through FastAPI’s lifespan hook in `app/main.py`. To disable the consumer (e.g., for local development without AWS), set `ENABLE_DOCUMENT_CONSUMER=false`.

---

## Known Limitations & Follow-ups

- **Missing RBAC on listing** – `GET /documents/{entity_id}` does not accept a requester ID and bypasses `EprService`; any caller able to reach the API can enumerate documents for any entity. Add a requester parameter, enforce authorization, and audit the access.
- **AWS credential handling** – `StorageService`, `AuditEventPublisher`, and the consumer insist on static `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`. This breaks IAM role-based deployments (ECS/EKS). Refactor to rely on the default credential chain and only require explicit keys when provided.
- **Configuration duplication** – `Settings` declares `epr_service_url` and `presigned_url_expiration_seconds` twice. The duplicates override alias-based parsing, so environment overrides are ignored (notably for presigned URL expiry). Consolidate these definitions.
- **Presigned URL generation** – `StorageService.generate_presigned_url` awaits `generate_presigned_url`, which is synchronous in aioboto3/aiobotocore. Remove the `await` or wrap in `asyncio.to_thread` to avoid `'str' object is not awaitable` errors at runtime.
- **Duplicate hash race condition** – Application logic blocks duplicate documents (same `entity_id` + hash) but the database lacks a unique constraint. Add a partial unique index to enforce this at the DB level and prevent race-created duplicates.
- **Consumer dedup rollback** – When `_mark_processed` hits an `IntegrityError`, it issues `session.rollback()` which also undoes any document archival performed earlier in the transaction. Handle the race more carefully (e.g., flush in a savepoint or reapply the archival after rollback).
- **Large file memory usage** – `StorageService.upload_document` reads the entire file into memory before uploading. For very large files, consider streaming upload (e.g., multipart upload or resetting to chunked streaming).
- **Real secrets in `.env`** – The committed `.env` contains real-looking AWS credentials and bucket names. Rotate those secrets immediately and replace the file with safe placeholders.

---

## Additional Documentation

- `Document Vault Overview.md` – high-level architecture notes.
- `CONSUMER_IMPLEMENTATION.md` – detailed background consumer design.

---

## Versioning

- **Current service version:** 1.0.0
- **Self-review completed:** November 2025

Please keep this README up to date when the API surface, integrations, or deployment assumptions change.
