from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Sequence
from uuid import UUID

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logger import get_logger
from app.events.publisher import DocumentEventPublisher
from app.models.document import (
    Document,
    DocumentAuditEvent,
    DocumentEntityType,
    DocumentSignatureState,
    DocumentStatus,
)
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.epr_service import EprService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService

logger = get_logger(component="DocumentService")


class DocumentNotFoundError(Exception):
    """Raised when attempting to operate on a missing document."""


class InvalidFileTypeError(Exception):
    """Raised when file MIME type is not allowed."""


class FileSizeExceededError(Exception):
    """Raised when file size exceeds maximum limit."""


class DuplicateDocumentError(Exception):
    """Raised when attempting to upload a duplicate document (same hash)."""


class InvalidSignedUrlExpiryError(Exception):
    """Raised when signed URL expiry exceeds maximum allowed time."""


class UnauthorizedAccessError(Exception):
    """Raised when user lacks required permissions for document access."""


class DocumentService:
    def __init__(
        self,
        storage_service: StorageService,
        hashing_service: HashingService,
        audit_event_publisher: AuditEventPublisher,
        access_control_service: EprService | EprServiceMock,
        blockchain_service: BlockchainService,
        event_publisher: DocumentEventPublisher,
    ) -> None:
        self.storage_service = storage_service
        self.hashing_service = hashing_service
        self.audit_event_publisher = audit_event_publisher
        self.access_control_service = access_control_service
        self.blockchain_service = blockchain_service
        self.event_publisher = event_publisher

    def _validate_file_type(self, mime_type: str) -> None:
        """Validate that the file MIME type is allowed."""
        if mime_type not in settings.allowed_mime_types:
            logger.warning(
                "Invalid file type attempted",
                mime_type=mime_type,
                allowed_types=settings.allowed_mime_types,
            )
            raise InvalidFileTypeError(
                f"File type '{mime_type}' is not allowed. "
                f"Allowed types: {', '.join(settings.allowed_mime_types)}"
            )

    def _validate_file_size(self, size_bytes: int) -> None:
        """Validate that the file size does not exceed the maximum limit."""
        max_size_mb = settings.max_upload_file_size_bytes / (1024 * 1024)
        if size_bytes > settings.max_upload_file_size_bytes:
            logger.warning(
                "File size exceeded",
                size_bytes=size_bytes,
                max_allowed=settings.max_upload_file_size_bytes,
            )
            raise FileSizeExceededError(
                f"File size ({size_bytes} bytes) exceeds maximum allowed size "
                f"({settings.max_upload_file_size_bytes} bytes / {max_size_mb:.1f}MB)"
            )

    async def _check_duplicate_hash(self, session: AsyncSession, sha256_hash: str, entity_id: UUID) -> None:
        """Check if a document with the same hash already exists for this entity."""
        if not settings.enable_duplicate_hash_detection:
            return

        result = await session.execute(
            select(Document).where(
                Document.sha256_hash == sha256_hash,
                Document.entity_id == entity_id,
                Document.status != DocumentStatus.ARCHIVED,
            )
        )
        existing_document = result.scalar_one_or_none()
        
        if existing_document:
            logger.warning(
                "Duplicate document detected",
                sha256_hash=sha256_hash,
                entity_id=str(entity_id),
                existing_document_id=str(existing_document.id),
            )
            raise DuplicateDocumentError(
                f"A document with the same content already exists for this entity "
                f"(Document ID: {existing_document.id})"
            )

    async def upload_document(
        self, session: AsyncSession, *, file: UploadFile, metadata: DocumentUploadMetadata
    ) -> Document:
        # Authorization check
        is_allowed = await self.access_control_service.is_authorized(
            user_id=metadata.uploaded_by, action="document:upload", resource_id=metadata.entity_id
        )
        if not is_allowed:
            logger.warning(
                "Upload not authorized",
                user_id=str(metadata.uploaded_by),
                entity_id=str(metadata.entity_id),
            )
            raise PermissionError("Upload not authorized")

        # Get file metadata
        underlying_file = file.file
        mime_type = file.content_type or "application/octet-stream"
        filename = file.filename or "document"

        # Validate MIME type
        self._validate_file_type(mime_type)

        # Get file size
        underlying_file.seek(0, os.SEEK_END)
        size_bytes = underlying_file.tell()
        underlying_file.seek(0)

        # Validate file size
        self._validate_file_size(size_bytes)

        # Compute hash
        underlying_file.seek(0)
        sha256_hash = self.hashing_service.compute_sha256(underlying_file)
        
        # Check for duplicates
        await self._check_duplicate_hash(session, sha256_hash, metadata.entity_id)

        underlying_file.seek(0)

        # Upload to S3
        logger.info(
            "Uploading document to S3",
            filename=filename,
            mime_type=mime_type,
            size_bytes=size_bytes,
            entity_id=str(metadata.entity_id),
        )
        
        storage_key, version_id = await self.storage_service.upload_document(
            underlying_file,
            filename=filename,
            mime_type=mime_type,
        )

        # Create document record
        document = Document(
            entity_type=metadata.entity_type,
            entity_id=metadata.entity_id,
            token_id=metadata.token_id,
            document_type=metadata.document_type,
            filename=filename,
            mime_type=mime_type,
            size_bytes=size_bytes,
            storage_bucket=settings.document_bucket,
            storage_key=storage_key,
            storage_version_id=version_id,
            sha256_hash=sha256_hash,
            status=DocumentStatus.UPLOADED,
            uploaded_by=metadata.uploaded_by,
            metadata_json=metadata.metadata.model_dump() if metadata.metadata else None,
            signature_state=DocumentSignatureState.NOT_REQUESTED,
        )
        session.add(document)
        await session.flush()

        # Publish audit event to centralized SNS topic
        await self.audit_event_publisher.publish_event(
            action=DocumentAuditEvent.UPLOAD.value,
            actor_id=metadata.uploaded_by,
            actor_type="user",
            entity_id=document.id,
            entity_type="document",
            details={
                "filename": document.filename,
                "mime_type": document.mime_type,
                "size_bytes": document.size_bytes,
                "sha256_hash": document.sha256_hash,
                "entity_type": document.entity_type.value,
                "entity_id": str(document.entity_id),
                "document_type": document.document_type.value,
            },
        )

        await self.event_publisher.publish(
            event_type=DocumentAuditEvent.UPLOAD.value,
            payload={
                "document_id": str(document.id),
                "entity_type": document.entity_type.value,
                "entity_id": str(document.entity_id),
                "sha256_hash": document.sha256_hash,
                "status": document.status.value,
            },
        )

        # Asynchronously trigger the verification workflow
        await self.access_control_service.trigger_document_verification_workflow(
            document_id=document.id,
            entity_id=document.entity_id,
            entity_type=document.entity_type.value,
            document_type=document.document_type.value,
        )

        logger.info("Document uploaded", document_id=str(document.id), storage_key=storage_key)
        return document

    async def verify_document(
        self, session: AsyncSession, *, document_id: UUID, verifier_id: UUID
    ) -> Document:
        document = await self._get_document(session, document_id)

        is_allowed = await self.access_control_service.is_authorized(
            user_id=verifier_id, action="document:verify", resource_id=document.entity_id
        )
        if not is_allowed:
            raise PermissionError("Verify not authorized")

        sha256_hash = self.hashing_service.create_digest()
        async for chunk in self.storage_service.stream_document(document.storage_key):
            sha256_hash.update(chunk)
        calculated_hash = sha256_hash.hexdigest()

        if calculated_hash == document.sha256_hash:
            document.status = DocumentStatus.VERIFIED
            document.hash_verified_at = datetime.now(tz=timezone.utc)
            document.verified_by = verifier_id
            document.on_chain_reference = await self.blockchain_service.register_document(
                token_id=document.token_id,
                document_hash=document.sha256_hash,
                metadata_uri=None,
            )
            # Publish audit event to centralized SNS topic
            await self.audit_event_publisher.publish_event(
                action=DocumentAuditEvent.VERIFIED.value,
                actor_id=verifier_id,
                actor_type="user",
                entity_id=document.id,
                entity_type="document",
                details={
                    "sha256_hash": document.sha256_hash,
                    "on_chain_reference": document.on_chain_reference,
                },
            )
            await self.event_publisher.publish(
                event_type=DocumentAuditEvent.VERIFIED.value,
                payload={
                    "document_id": str(document.id),
                    "entity_type": document.entity_type.value,
                    "entity_id": str(document.entity_id),
                    "sha256_hash": document.sha256_hash,
                },
            )
        else:
            document.status = DocumentStatus.MISMATCH
            # Publish audit event to centralized SNS topic
            await self.audit_event_publisher.publish_event(
                action=DocumentAuditEvent.MISMATCH.value,
                actor_id=verifier_id,
                actor_type="user",
                entity_id=document.id,
                entity_type="document",
                details={
                    "expected_hash": document.sha256_hash,
                    "calculated_hash": calculated_hash,
                },
            )
            await self.event_publisher.publish(
                event_type=DocumentAuditEvent.MISMATCH.value,
                payload={
                    "document_id": str(document.id),
                    "expected_hash": document.sha256_hash,
                    "calculated_hash": calculated_hash,
                    "entity_id": str(document.entity_id),
                },
            )
            
            # Publish integrity alert to compliance dashboard
            await self.event_publisher.publish_integrity_alert(
                document_id=document.id,
                filename=document.filename,
                entity_id=document.entity_id,
                entity_type=document.entity_type,
                expected_hash=document.sha256_hash,
                calculated_hash=calculated_hash,
                verified_by=verifier_id,
                severity="CRITICAL",
                recommended_action="FREEZE_ENTITY",
            )
            
            logger.warning(
                "Document integrity violation detected",
                document_id=str(document.id),
                filename=document.filename,
                entity_id=str(document.entity_id),
                expected_hash=document.sha256_hash,
                calculated_hash=calculated_hash,
                verified_by=str(verifier_id),
            )

        
        logger.info("Document verification processed", document_id=str(document.id), status=document.status.value)
        return document

    async def archive_document(
        self, session: AsyncSession, *, document_id: UUID, archived_by: UUID
    ) -> Document:
        """
        Archive (soft-delete) a document.
        
        The document is marked as ARCHIVED, not physically deleted.
        This preserves the record for audit and compliance purposes.
        
        Args:
            session: Database session
            document_id: UUID of document to archive
            archived_by: UUID of user archiving the document
        
        Returns:
            Archived document
        
        Raises:
            DocumentNotFoundError: Document doesn't exist
            PermissionError: User lacks archive permission
        """
        document = await self._get_document(session, document_id)

        is_allowed = await self.access_control_service.is_authorized(
            user_id=archived_by, action="document:archive", resource_id=document.entity_id
        )
        if not is_allowed:
            logger.warning(
                "Archive not authorized",
                user_id=str(archived_by),
                document_id=str(document_id),
                entity_id=str(document.entity_id),
            )
            raise PermissionError("Archive not authorized")

        previous_status = document.status
        document.status = DocumentStatus.ARCHIVED
        document.archived_at = datetime.now(tz=timezone.utc)
        document.archived_by = archived_by

        logger.info(
            "Document archived (soft delete)",
            document_id=str(document.id),
            filename=document.filename,
            previous_status=previous_status.value,
            archived_by=str(archived_by),
            archived_at=document.archived_at.isoformat(),
        )

        # Publish audit event to centralized SNS topic
        await self.audit_event_publisher.publish_event(
            action=DocumentAuditEvent.ARCHIVED.value,
            actor_id=archived_by,
            actor_type="user",
            entity_id=document.id,
            entity_type="document",
            details={
                "archived_at": document.archived_at.isoformat(),
                "filename": document.filename,
                "previous_status": previous_status.value,
            },
        )

        await self.event_publisher.publish(
            event_type=DocumentAuditEvent.ARCHIVED.value,
            payload={
                "document_id": str(document.id),
                "entity_id": str(document.entity_id),
                "entity_type": document.entity_type.value,
                "filename": document.filename,
                "archived_at": document.archived_at.isoformat(),
            },
        )

        
        return document

    async def relink_document(
        self,
        session: AsyncSession,
        *,
        document_id: UUID,
        new_entity_id: UUID,
        new_entity_type: DocumentEntityType,
        relinked_by: UUID,
        token_id: int | None = None,
    ) -> Document:
        """
        Reassign a document to a different entity while preserving audit history.

        Args:
            session: Database session
            document_id: Document being re-linked
            new_entity_id: Entity to associate the document with
            new_entity_type: Type of the new entity
            relinked_by: User performing the relink
            token_id: Optional token id to update (defaults to existing value)

        Returns:
            Updated document
        """
        document = await self._get_document(session, document_id)

        is_allowed = await self.access_control_service.is_authorized(
            user_id=relinked_by, action="document:relink", resource_id=new_entity_id
        )
        if not is_allowed:
            logger.warning(
                "Relink not authorized",
                user_id=str(relinked_by),
                document_id=str(document_id),
                new_entity_id=str(new_entity_id),
            )
            raise PermissionError("Relink not authorized")

        previous_entity_id = document.entity_id
        previous_entity_type = document.entity_type

        document.entity_id = new_entity_id
        document.entity_type = new_entity_type
        if token_id is not None:
            document.token_id = token_id

        await session.flush()

        await self.audit_event_publisher.publish_event(
            action=DocumentAuditEvent.RELINKED.value,
            actor_id=relinked_by,
            actor_type="user",
            entity_id=document.id,
            entity_type="document",
            details={
                "old_entity_id": str(previous_entity_id),
                "old_entity_type": previous_entity_type.value,
                "new_entity_id": str(new_entity_id),
                "new_entity_type": new_entity_type.value,
                "token_id": document.token_id,
            },
        )

        await self.event_publisher.publish(
            event_type=DocumentAuditEvent.RELINKED.value,
            payload={
                "document_id": str(document.id),
                "old_entity_id": str(previous_entity_id),
                "old_entity_type": previous_entity_type.value,
                "new_entity_id": str(new_entity_id),
                "new_entity_type": new_entity_type.value,
                "relinked_by": str(relinked_by),
            },
        )

        logger.info(
            "Document relinked",
            document_id=str(document.id),
            old_entity_id=str(previous_entity_id),
            new_entity_id=str(new_entity_id),
            relinked_by=str(relinked_by),
        )

        return document

    async def list_documents(
        self, session: AsyncSession, *, entity_id: UUID, include_archived: bool = False
    ) -> Sequence[Document]:
        """
        List documents for an entity.
        
        Args:
            session: Database session
            entity_id: UUID of the entity
            include_archived: If True, include archived documents. Default False (excludes archived).
        
        Returns:
            List of documents (excludes archived by default)
        """
        query = select(Document).where(
            Document.entity_id == entity_id
        )
        
        # Exclude archived documents by default
        if not include_archived:
            query = query.where(Document.status != DocumentStatus.ARCHIVED)
            logger.debug(
                "Listing documents (excluding archived)",
                entity_id=str(entity_id),
            )
        else:
            logger.debug(
                "Listing documents (including archived)",
                entity_id=str(entity_id),
            )
        
        result = await session.execute(query)
        documents = result.scalars().all()
        
        logger.info(
            "Documents listed",
            entity_id=str(entity_id),
            count=len(documents),
            include_archived=include_archived,
        )
        
        return documents

    async def get_document(self, session: AsyncSession, document_id: UUID) -> Document:
        return await self._get_document(session, document_id)

    async def generate_download_url(
        self, session: AsyncSession, *, document_id: UUID, requestor_id: UUID, expires_in_seconds: int | None = None
    ) -> tuple[Document, str]:
        """
        Generate a presigned download URL for a document.
        
        Args:
            session: Database session
            document_id: ID of document to download
            requestor_id: ID of user requesting download
            expires_in_seconds: Optional custom expiry (must be <= max allowed)
        
        Returns:
            Tuple of (Document, presigned_url)
        
        Raises:
            DocumentNotFoundError: Document doesn't exist
            UnauthorizedAccessError: User lacks permission
            InvalidSignedUrlExpiryError: Expiry exceeds maximum
        """
        document = await self._get_document(session, document_id)
        
        # Authorization check
        is_allowed = await self.access_control_service.is_authorized(
            user_id=requestor_id, action="document:download", resource_id=document.entity_id
        )
        if not is_allowed:
            logger.warning(
                "Download not authorized",
                user_id=str(requestor_id),
                document_id=str(document_id),
                entity_id=str(document.entity_id),
            )
            raise UnauthorizedAccessError(
                f"User {requestor_id} is not authorized to download document {document_id}"
            )
        
        # Validate expiry time
        expiry = expires_in_seconds if expires_in_seconds is not None else settings.presigned_url_expiration_seconds
        max_expiry = 3600  # 1 hour maximum
        
        if expiry > max_expiry:
            logger.warning(
                "Signed URL expiry exceeds maximum",
                requested_expiry=expiry,
                max_allowed=max_expiry,
                document_id=str(document_id),
            )
            raise InvalidSignedUrlExpiryError(
                f"Signed URL expiry ({expiry}s) exceeds maximum allowed ({max_expiry}s / 1 hour)"
            )
        
        logger.info(
            "Generating presigned download URL",
            document_id=str(document_id),
            requestor_id=str(requestor_id),
            expiry_seconds=expiry,
        )
        
        url = await self.storage_service.generate_presigned_url(
            document.storage_key, expires_in_seconds=expiry
        )
        return document, url

    async def _get_document(self, session: AsyncSession, document_id: UUID) -> Document:
        result = await session.execute(select(Document).where(Document.id == document_id))
        document = result.scalar_one_or_none()
        if document is None:
            raise DocumentNotFoundError(f"Document {document_id} not found")
        return document

    async def cascade_archive_by_entity(
        self, session: AsyncSession, *, entity_id: UUID, entity_type: DocumentEntityType, archived_by: UUID | None = None
    ) -> int:
        """
        Archive all documents associated with a given entity.
        
        This is typically called when an entity is deleted from the system,
        and we need to cascade the archival to all related documents.
        
        Args:
            session: Database session
            entity_id: UUID of the entity being deleted
            entity_type: Type of the entity (issuer, investor, deal, etc.)
            archived_by: Optional UUID of the user/system performing the archival
        
        Returns:
            Number of documents archived
        """
        # Query all non-archived documents for this entity
        result = await session.execute(
            select(Document).where(
                Document.entity_id == entity_id,
                Document.entity_type == entity_type,
                Document.status != DocumentStatus.ARCHIVED
            )
        )
        documents = result.scalars().all()
        
        archived_count = 0
        now = datetime.now(tz=timezone.utc)
        
        for document in documents:
            document.status = DocumentStatus.ARCHIVED
            document.archived_at = now
            document.archived_by = archived_by
            
            # Publish audit event for each archived document
            await self.audit_event_publisher.publish_event(
                action=DocumentAuditEvent.ARCHIVED.value,
                actor_id=archived_by,
                actor_type="system",
                entity_id=document.id,
                entity_type="document",
                details={
                    "archived_at": now.isoformat(),
                    "reason": "entity_deleted",
                    "source_entity_id": str(entity_id),
                    "source_entity_type": entity_type.value,
                },
            )
            
            # Publish document event
            await self.event_publisher.publish(
                event_type=DocumentAuditEvent.ARCHIVED.value,
                payload={
                    "document_id": str(document.id),
                    "entity_id": str(entity_id),
                    "entity_type": entity_type.value,
                    "reason": "entity_deleted",
                },
            )
            
            archived_count += 1
        
        logger.info(
            "Cascade archived documents for entity",
            entity_id=str(entity_id),
            entity_type=entity_type.value,
            archived_count=archived_count,
        )
        
        return archived_count
