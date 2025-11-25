from __future__ import annotations

import inspect
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logger import get_logger
from app.events.publisher import DocumentEventPublisher
from app.models.document import Document, DocumentAuditEvent, DocumentSignatureState, DocumentStatus
from app.schemas.document import DocumentSignatureRequest, DocumentSignerAssignment
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.document_service import DocumentNotFoundError, DocumentService
from app.services.docusign_service import (
    DocuSignConfigurationError,
    DocuSignConsentRequiredError,
    DocuSignRecipient,
    DocuSignService,
)
from app.services.user_directory_service import UserDirectoryError, UserDirectoryService, UserNotFoundError

logger = get_logger(component="DocumentSignatureService")


class SignatureOperationError(Exception):
    """Raised for invalid signature operations."""


class DocumentSignatureService:
    def __init__(
        self,
        *,
        document_service: DocumentService,
        docusign_service: DocuSignService,
        user_directory_service: UserDirectoryService,
        audit_event_publisher: AuditEventPublisher,
        event_publisher: DocumentEventPublisher,
    ) -> None:
        self._document_service = document_service
        self._docusign_service = docusign_service
        self._user_directory_service = user_directory_service
        self._audit_event_publisher = audit_event_publisher
        self._event_publisher = event_publisher

    async def request_signatures(
        self,
        session: AsyncSession,
        *,
        document_id: UUID,
        payload: DocumentSignatureRequest,
        requested_by: UUID,
    ) -> Document:
        document = await self._document_service.get_document(session, document_id)
        if document.status == DocumentStatus.ARCHIVED:
            raise SignatureOperationError("Cannot request signatures for archived documents")
        if document.signature_state in {DocumentSignatureState.PENDING, DocumentSignatureState.PARTIAL}:
            raise SignatureOperationError("Signature request already in progress for this document")

        resolved_signers = await self._resolve_signers(payload.signers)
        if not resolved_signers:
            raise SignatureOperationError("At least one signer is required")

        storage_service = self._document_service.storage_service
        document_bytes = await storage_service.download_document_bytes(document.storage_key)

        signer_payloads: list[tuple[dict[str, Any], str]] = []
        docusign_signers: list[DocuSignRecipient] = []
        for idx, signer in enumerate(resolved_signers):
            # Prefer the caller-provided signer_id for round-tripping in webhooks,
            # otherwise fall back to email, then positional index.
            recipient_id = str(signer.get("signer_id") or signer["email"] or idx + 1)
            routing_order = signer.get("routing_order") or idx + 1
            docusign_signers.append(
                DocuSignRecipient(
                    email=signer["email"],
                    name=signer["name"],
                    routing_order=routing_order,
                    recipient_id=recipient_id,
                )
            )
            signer_payloads.append((signer, recipient_id))

        try:
            envelope_id, recipient_map = await self._docusign_service.create_envelope(
                document_id=str(document.id),
                document_name=document.filename,
                document_bytes=document_bytes,
                signers=docusign_signers,
                email_subject=payload.email_subject or f"Signature request for {document.filename}",
                email_body=payload.email_body,
            )
        except DocuSignConsentRequiredError as exc:
            logger.error(
                "DocuSign consent required",
                document_id=str(document.id),
                consent_url=exc.consent_url,
            )
            raise SignatureOperationError(str(exc)) from exc
        except DocuSignConfigurationError as exc:
            logger.exception("DocuSign configuration error", document_id=str(document.id), error=str(exc))
            raise SignatureOperationError(f"DocuSign configuration error: {exc}") from exc
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("DocuSign envelope creation failed", document_id=str(document.id), error=str(exc))
            raise SignatureOperationError("Unable to create DocuSign envelope") from exc

        now = datetime.now(tz=timezone.utc).isoformat()
        document.signatures_json = []
        for signer, recipient_id in signer_payloads:
            mapped_recipient_id = recipient_map.get(signer["email"]) or recipient_id
            document.signatures_json.append(
                {
                    "signer_id": signer.get("signer_id"),
                    "email": signer["email"],
                    "name": signer.get("name"),
                    "role": signer.get("role"),
                    "routing_order": signer.get("routing_order"),
                    "signed": False,
                    "signature_requested_at": now,
                    "signature_completed_at": None,
                    "docusign_recipient_id": mapped_recipient_id,
                }
            )

        document.signature_state = DocumentSignatureState.PENDING
        document.signature_envelope_id = envelope_id
        await self._session_add(session, document)

        await self._audit_event_publisher.publish_event(
            action=DocumentAuditEvent.SIGNATURE_REQUESTED.value,
            actor_id=requested_by,
            actor_type="user",
            entity_id=document.id,
            entity_type="document",
            details={
                "envelope_id": envelope_id,
                "signers": [signer["email"] for signer in resolved_signers],
            },
        )
        await self._event_publisher.publish(
            event_type=DocumentAuditEvent.SIGNATURE_REQUESTED.value,
            payload={
                "document_id": str(document.id),
                "envelope_id": envelope_id,
                "signers": [signer["email"] for signer in resolved_signers],
            },
        )

        return document

    async def process_webhook_notification(self, session: AsyncSession, envelope_id: str, recipient_updates: list[dict[str, Any]]) -> None:
        document = await self._get_document_by_envelope(session, envelope_id)
        if not document:
            logger.warning("Received DocuSign webhook for unknown envelope", envelope_id=envelope_id)
            return

        updated = False

        def _norm_email(value: Any) -> str:
            return str(value).strip().lower() if value else ""

        email_map = {_norm_email(update.get("email")): update for update in recipient_updates if update.get("email")}
        id_map = {str(update.get("recipientId")): update for update in recipient_updates if update.get("recipientId")}
        guid_map = {str(update.get("recipientIdGuid")): update for update in recipient_updates if update.get("recipientIdGuid")}

        new_signatures: list[dict[str, Any]] = []
        for signer in document.signatures_json or []:
            update = None

            # Prefer matching by email for robustness across payload shapes
            email_key = _norm_email(signer.get("email"))
            if email_key and email_key in email_map:
                update = email_map[email_key]

            # Fallback to recipient id/guid if email is missing in payload
            if update is None:
                recipient_id = signer.get("docusign_recipient_id") or signer.get("recipient_id")
                if recipient_id:
                    update = id_map.get(str(recipient_id)) or guid_map.get(str(recipient_id))

            if update:
                status = (update.get("status") or "").lower()
                if status == "completed" and not signer.get("signed"):
                    signer = dict(signer)
                    signer["signed"] = True
                    signer["signature_completed_at"] = datetime.now(tz=timezone.utc).isoformat()
                    updated = True
                    logger.info(
                        "DocuSign signer marked completed",
                        envelope_id=envelope_id,
                        signer_email=signer.get("email"),
                        recipient_id=signer.get("docusign_recipient_id"),
                    )
            else:
                logger.debug(
                    "DocuSign signer update not found for webhook payload",
                    envelope_id=envelope_id,
                    signer_email=signer.get("email"),
                    signer_recipient_id=signer.get("docusign_recipient_id"),
                )

            new_signatures.append(signer)

        if not updated:
            return

        # Assign the signatures_json anew so SQLAlchemy detects the mutation
        document.signatures_json = new_signatures
        document.signature_state = self._compute_signature_state(document)
        await self._session_add(session, document)
        logger.info(
            "DocuSign webhook processed and persisted",
            envelope_id=envelope_id,
            signature_state=document.signature_state.value if hasattr(document.signature_state, "value") else str(document.signature_state),
        )

        if document.signature_state == DocumentSignatureState.COMPLETED:
            await self._emit_all_signed_events(document)

    async def download_signed_document(self, envelope_id: str) -> bytes:
        """
        Download the completed signed document from DocuSign.
        
        Args:
            envelope_id: DocuSign envelope ID
            
        Returns:
            Document bytes (PDF with signatures)
        """
        return await self._docusign_service.download_completed_document(
            envelope_id=envelope_id,
            document_id="combined",  # "combined" returns the final merged PDF with all signatures
        )

    async def _emit_all_signed_events(self, document: Document) -> None:
        await self._audit_event_publisher.publish_event(
            action=DocumentAuditEvent.SIGNATURE_COMPLETED.value,
            actor_id=None,
            actor_type="system",
            entity_id=document.id,
            entity_type="document",
            details={
                "signers": [entry["email"] for entry in document.signatures_json or []],
            },
        )
        await self._event_publisher.publish(
            event_type=DocumentAuditEvent.SIGNATURE_COMPLETED.value,
            payload={
                "document_id": str(document.id),
                "signers": [entry["email"] for entry in document.signatures_json or []],
            },
        )

    async def _resolve_signers(self, signers: list[DocumentSignerAssignment]) -> list[dict[str, Any]]:
        resolved: list[dict[str, Any]] = []
        for signer in signers:
            signer_id = signer.user_id
            email = signer.email
            name = signer.name
            try:
                user_record = None
                if signer_id:
                    user_record = await self._user_directory_service.get_user(signer_id)
                elif email:
                    user_record = await self._user_directory_service.get_user_by_email(email)
            except UserNotFoundError as exc:
                raise SignatureOperationError(str(exc)) from exc
            except UserDirectoryError as exc:
                logger.warning("User directory lookup failed, falling back to provided payload", error=str(exc))
                user_record = None

            if user_record:
                signer_id = UUID(user_record["id"]) if user_record.get("id") else signer_id
                email = user_record.get("email", email)
                if not name:
                    first = user_record.get("first_name")
                    last = user_record.get("last_name")
                    name = " ".join(part for part in [first, last] if part)

            if not email:
                raise SignatureOperationError("Signer email is required")

            resolved.append(
                {
                    "signer_id": str(signer_id) if signer_id else None,
                    "email": email,
                    "name": name or email.split("@")[0],
                    "role": signer.role,
                    "routing_order": signer.routing_order,
                }
            )
        return resolved

    async def _get_document_by_envelope(self, session: AsyncSession, envelope_id: str) -> Document | None:
        stmt = select(Document).where(Document.signature_envelope_id == envelope_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    def _compute_signature_state(self, document: Document) -> DocumentSignatureState:
        signatures = document.signatures_json or []
        if not signatures:
            return DocumentSignatureState.NOT_REQUESTED
        completed = [entry for entry in signatures if entry.get("signed")]
        if len(completed) == len(signatures):
            return DocumentSignatureState.COMPLETED
        if completed:
            return DocumentSignatureState.PARTIAL
        return DocumentSignatureState.PENDING

    async def _session_add(self, session: AsyncSession, obj: Any) -> None:
        result = session.add(obj)
        if inspect.isawaitable(result):
            await result
