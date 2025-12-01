# Document Vault – Overview

Document Vault is Omen's legal-truth service. It ingests, stores, verifies, and routes lifecycle events for compliance documents that back tokenized assets. The service runs as a FastAPI app with a background SQS consumer and integrates with AWS (S3/SQS), DocuSign, and the Entity & Permissions (EPR) platform.

---

## Responsibilities

- **Document lifecycle** – upload, list, relink, verify, archive; metadata lives in Postgres, binaries in S3 with SSE-KMS.
- **Integrity & trust** – SHA-256 hashing on upload and re-hash verification; integrity alerts on mismatch.
- **Access control** – calls EPR for authorization (or a mock RBAC mode in local/test).
- **Events & audit** – document lifecycle events to SQS, audit events to the EPR API, optional compliance alerts to a separate queue.
- **Cascade archival** – background consumer listens for `entity.deleted` events to soft-archive related documents.
- **Signatures** – DocuSign envelope creation, webhook reconciliation, and signed-document download.

---

## Architecture at a Glance

| Concern | Implementation |
|---------|----------------|
| API | FastAPI routers in `app/api/routes`, Pydantic v2 schemas in `app/schemas/document.py` |
| Persistence | Async SQLAlchemy models `documents` and `document_vault_processed_events` in `app/models` (Postgres by default) |
| Storage | `StorageService` (aioboto3) uploads to S3 with SSE-KMS and issues presigned download URLs |
| Access | `EprService` HTTP client or `EprServiceMock` role-based grant when `EPR_MOCK_MODE=true` |
| Hashing | `HashingService` streams SHA-256; duplicate detection optional |
| Events | `DocumentEventPublisher` -> SQS lifecycle + integrity alerts; `AuditEventPublisher` -> EPR API |
| Signatures | `DocumentSignatureService` + `DocuSignService` (JWT auth) + `UserDirectoryService` for signer resolution |
| Background | `DocumentVaultConsumer` SQS poller for cascade archival, wired in `app/main.py` lifespan hook |
| Blockchain | `BlockchainService` stub that logs and returns deterministic tx ids |

---

## Primary Flows

| Flow | What happens |
|------|--------------|
| **Upload** (`POST /api/v1/documents/upload`) | Auth via EPR -> validate MIME/size -> hash -> duplicate check (per entity) -> upload to S3 -> insert row -> publish `document.uploaded` + audit -> trigger EPR document-verification workflow. |
| **Verify** (`POST /api/v1/documents/verify`) | Auth -> stream from S3 and re-hash -> set status `verified` or `mismatch`; on match register on-chain ref (mock), emit lifecycle + audit; on mismatch also publish integrity alert to compliance queue. |
| **Download** (`GET /api/v1/documents/{id}/download?requestor_id=...`) | Auth -> generate presigned URL (capped at 1h) -> return URL + expiry. |
| **List** (`GET /api/v1/documents/{entity_id}`) | Returns non-archived documents for the entity (no requester auth currently). |
| **Relink** (`POST /api/v1/documents/{id}/relink`) | Auth -> move document to a new entity/token id -> emit `document.relinked` + audit. |
| **Archive** (`DELETE /api/v1/documents/{id}`) | Auth -> soft-delete (status `archived`) -> emit lifecycle + audit. |
| **Cascade archive** | `DocumentVaultConsumer` handles `entity.deleted` SQS messages -> archives all non-archived docs for that entity -> records dedup row. |
| **Signatures** | `POST /{id}/signatures/request` creates DocuSign envelope, stores signer state, emits `document.signature_requested`; webhook `/signatures/webhook/docusign` reconciles signer status; `GET /{id}/signatures/signed-document` downloads final PDF when `COMPLETED`. |

---

## Components & Boundaries

- **API surface** – Endpoints mount under `/api/v1/documents`. Exception handlers live in `app/main.py`. Health probe at `/healthz`.
- **`DocumentService` (`app/services/document_service.py`)** – Orchestrates auth, validation, hashing, storage, DB writes, events, audit, blockchain stub, and cascade archival.
- **`StorageService`** – aioboto3 client; uploads load the entire file into memory; presigned URL helper is awaited (aioboto3's method is sync—see caveats).
- **`AuditEventPublisher`** – Posts to `EPR_SERVICE_URL/api/v1/events`; skipped if URL unset.
- **`DocumentEventPublisher`** – Sends lifecycle payloads to `DOCUMENT_EVENTS_QUEUE_URL`; integrity alerts go to `COMPLIANCE_ALERT_QUEUE_URL` when configured.
- **`EprService` / `EprServiceMock`** – Authorization checks + workflow trigger. Mock grants everything unless seeded with role maps.
- **`DocumentSignatureService`** – Coordinates DocuSign (JWT), signer resolution via user directory, envelope creation, webhook handling, signed-PDF download.
- **`UserDirectoryService`** – Optional user lookup by id/email to enrich signer name/email; uses `USER_DIRECTORY_BASE_URL`.
- **`DocumentVaultConsumer`** – Long-polls `DOCUMENT_VAULT_SQS_URL`; deduplicates via `document_vault_processed_events`; archives docs transactionally.

---

## Data Model Snapshot

- **`documents`**  
  - Entity linkage: `entity_type` (`issuer`/`investor`/`deal`/`token`/`compliance`/`offering`), `entity_id`, optional `token_id`.  
  - File metadata: `filename`, `mime_type`, `size_bytes`, `storage_bucket`, `storage_key`, `storage_version_id`.  
  - Integrity: `sha256_hash`, `status` (`uploaded`, `verified`, `mismatch`, `archived`), `hash_verified_at`, `on_chain_reference`.  
  - Actors & audit: `uploaded_by`, `verified_by`, `archived_by`, `archived_at`, JSON `metadata`.  
  - Signatures: JSON array of signer entries, `signature_state` (`NOT_REQUESTED`, `PENDING`, `PARTIAL`, `COMPLETED`), `signature_envelope_id`.  
- **`document_vault_processed_events`** – Dedup for consumer (`event_id` unique, plus source/action/entity metadata).

---

## Events & Contracts

- **Lifecycle events** (SQS `DOCUMENT_EVENTS_QUEUE_URL`):  
  `document.uploaded`, `document.verified`, `document.mismatch`, `document.archived`, `document.relinked`, `document.signature_requested`, `document.signature_completed`.  
  Envelope:  
  ```json
  {
    "event_type": "document.uploaded",
    "occurred_at": "2025-01-01T12:00:00Z",
    "payload": {
      "document_id": "uuid",
      "entity_id": "uuid",
      "entity_type": "issuer",
      "sha256_hash": "..."
    }
  }
  ```
- **Integrity alerts** (optional `COMPLIANCE_ALERT_QUEUE_URL`): payload includes `alert_type=integrity_violation`, `document_id`, `entity_id`, `expected_hash`, `calculated_hash`, `verified_by`, `severity`, `recommended_action`.
- **Audit events** (HTTP to EPR): `AuditEventPublisher.publish_event` sends `{ event_type, source=document_vault, payload, context }` to `/api/v1/events`; skips when `EPR_SERVICE_URL` unset.
- **DocuSign webhook**: accepts camelCase or PascalCase keys; extracts `envelopeId` and signer status from `recipients.signers` or nested `data.envelopeSummary`.

---

## Configuration (env-driven in `app/core/config.py`)

- **Database**: `DATABASE_URL` (+ pool settings).
- **AWS/S3**: `AWS_REGION`, optional profile/keys, `DOCUMENT_VAULT_BUCKET`, `AWS_S3_KMS_KEY_ID`, optional `AWS_S3_ENDPOINT_URL`.
- **Events**: `DOCUMENT_EVENTS_QUEUE_URL`, optional `COMPLIANCE_ALERT_QUEUE_URL`.
- **Access control**: `EPR_MOCK_MODE`, `EPR_SERVICE_URL`, `EPR_SERVICE_TIMEOUT`.
- **Consumer**: `ENABLE_DOCUMENT_CONSUMER`, `DOCUMENT_VAULT_SQS_URL`, `DOCUMENT_CONSUMER_MAX_MESSAGES`, `DOCUMENT_CONSUMER_WAIT_TIME`, optional visibility timeout.
- **DocuSign**: base/auth paths, account/integration/user ids, `DOCUSIGN_PRIVATE_KEY`, optional `DOCUSIGN_WEBHOOK_SECRET`.
- **User directory**: `USER_DIRECTORY_BASE_URL`, optional `USER_DIRECTORY_API_KEY`.
- **Upload validation**: `MAX_UPLOAD_FILE_SIZE_BYTES` (100 MiB default), `ALLOWED_MIME_TYPES`, `ENABLE_DUPLICATE_HASH_DETECTION`.
- **Presigned URLs**: `PRESIGNED_URL_EXPIRATION_SECONDS` (default 900; code caps expiry at 3600s and currently ignores env override because the setting is duplicated—see caveats).
- **Logging**: `LOG_LEVEL`, `LOG_FORMAT`.

---

## Integration Notes for Downstream Services

- **Consume SQS events** to mirror document lifecycle or trigger follow-on workflows. Integrity alerts may land on a separate queue if configured.
- **Call EPR** for your own authorization; the Document Vault list endpoint currently does not enforce requester context.
- **DocuSign**: configure Connect to `POST /api/v1/documents/signatures/webhook/docusign`; see `docs/DocuSign_Integration.md` for detailed setup.
- **Entity deletion**: emit `entity.deleted` events (SNS -> SQS) with `{event_id, source, action, entity_id, entity_type}`; the consumer archives related docs.
- **Audit**: audit records live in EPR; ensure `EPR_SERVICE_URL` is reachable from deployments that need auditing.

---

## Operational Caveats & TODOs

1. Listing endpoint lacks requester auth; any caller can enumerate documents for an entity.
2. `StorageService.generate_presigned_url` awaits a sync method in aioboto3; adjust to avoid `'str' object is not awaitable` at runtime.
3. Duplicate hash protection is application-level only; DB lacks a unique constraint on `(entity_id, sha256_hash)`.
4. Consumer dedup rollback can undo archival when `_mark_processed` hits an `IntegrityError`; needs safer transactional handling.
5. Upload reads full file into memory; consider streaming/multipart uploads for large files.
6. `PRESIGNED_URL_EXPIRATION_SECONDS` is defined twice in settings; env override is ignored (defaults to 3600).
7. `.env` in the repo contains real-looking secrets—rotate/replace with safe placeholders.

---

## References

- API & setup: `README.md`
- DocuSign specifics: `docs/DocuSign_Integration.md`
- Consumer deep dive: `CONSUMER_IMPLEMENTATION.md`
- Tests: `tests/` (Pytest; heavy use of mocks for AWS/EPR/DocuSign)

*Last updated: 2025-11-14*
