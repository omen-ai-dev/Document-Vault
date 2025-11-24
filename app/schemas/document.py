from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationInfo, field_validator

from app.models.document import (
    Document,
    DocumentAuditEvent,
    DocumentEntityType,
    DocumentSignatureState,
    DocumentStatus,
    DocumentType,
)


class DocumentMetadata(BaseModel):
    description: str | None = None
    tags: list[str] | None = None
    extra: dict[str, Any] | None = None


class DocumentUploadMetadata(BaseModel):
    entity_id: UUID
    entity_type: DocumentEntityType
    document_type: DocumentType
    uploaded_by: UUID
    token_id: int | None = Field(default=None)
    metadata: DocumentMetadata | None = Field(default=None)


class DocumentVerifyRequest(BaseModel):
    document_id: UUID
    verifier_id: UUID


class DocumentRelinkRequest(BaseModel):
    new_entity_id: UUID
    new_entity_type: DocumentEntityType
    relinked_by: UUID
    token_id: int | None = None


class DocumentDownloadResponse(BaseModel):
    document_id: UUID
    download_url: str
    expires_in_seconds: int


class DocumentSignerAssignment(BaseModel):
    user_id: UUID | None = None
    email: EmailStr | None = None
    name: str | None = None
    role: str | None = None
    routing_order: int = 1

    @field_validator("email")
    @classmethod
    def require_identifier(cls, value, info: ValidationInfo):  # type: ignore[override]
        if value is None and (info.data.get("user_id") is None):
            raise ValueError("Either user_id or email must be provided for a signer")
        return value


class DocumentSignatureRequest(BaseModel):
    requested_by: UUID
    signers: list[DocumentSignerAssignment]
    email_subject: str | None = None
    email_body: str | None = None


class DocumentSignatureSummary(BaseModel):
    signer_id: UUID | None = None
    email: EmailStr
    name: str | None = None
    role: str | None = None
    routing_order: int | None = None
    signed: bool = False
    signature_requested_at: datetime | None = None
    signature_completed_at: datetime | None = None


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    entity_type: DocumentEntityType
    entity_id: UUID
    token_id: int | None
    document_type: DocumentType
    filename: str
    mime_type: str
    size_bytes: int
    storage_bucket: str
    storage_key: str
    sha256_hash: str
    status: DocumentStatus
    uploaded_by: UUID
    verified_by: UUID | None
    archived_by: UUID | None
    archived_at: datetime | None
    hash_verified_at: datetime | None
    on_chain_reference: str | None
    metadata: dict[str, Any] | None = Field(default=None, alias="metadata_json")
    signature_state: DocumentSignatureState | None
    signatures: list[DocumentSignatureSummary] | None = Field(default=None, alias="signatures_summary")
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, document: Document) -> "DocumentResponse":
        signatures_json = getattr(document, "signatures_json", None)
        signatures_data = []
        for entry in signatures_json or []:
            signer_uuid = None
            signer_id_raw = entry.get("signer_id")
            if signer_id_raw:
                try:
                    signer_uuid = UUID(signer_id_raw)
                except (ValueError, TypeError):
                    signer_uuid = None
            signatures_data.append(
                DocumentSignatureSummary(
                    signer_id=signer_uuid,
                    email=entry["email"],
                    name=entry.get("name"),
                    role=entry.get("role"),
                    routing_order=entry.get("routing_order"),
                    signed=bool(entry.get("signed")),
                    signature_requested_at=entry.get("signature_requested_at"),
                    signature_completed_at=entry.get("signature_completed_at"),
                )
            )
        return cls(
            id=document.id,
            entity_type=document.entity_type,
            entity_id=document.entity_id,
            token_id=document.token_id,
            document_type=document.document_type,
            filename=document.filename,
            mime_type=document.mime_type,
            size_bytes=document.size_bytes,
            storage_bucket=document.storage_bucket,
            storage_key=document.storage_key,
            sha256_hash=document.sha256_hash,
            status=document.status,
            uploaded_by=document.uploaded_by,
            verified_by=document.verified_by,
            archived_by=document.archived_by,
            archived_at=document.archived_at,
            hash_verified_at=document.hash_verified_at,
            on_chain_reference=document.on_chain_reference,
            metadata_json=document.metadata_json,
            signature_state=getattr(document, "signature_state", None),
            signatures_summary=signatures_data or None,
            created_at=document.created_at,
            updated_at=document.updated_at,
        )


class DocumentListResponse(BaseModel):
    documents: list[DocumentResponse]


class DocumentDeleteResponse(BaseModel):
    document_id: UUID
    status: DocumentStatus
    archived_at: datetime | None
