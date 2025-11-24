from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import JSON, Enum as SAEnum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, PrimaryKeyUUIDMixin, TimestampMixin
from app.models.types import GUID


class DocumentStatus(str, PyEnum):
    UPLOADED = "uploaded"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    ARCHIVED = "archived"


class DocumentEntityType(str, PyEnum):
    ISSUER = "issuer"
    INVESTOR = "investor"
    DEAL = "deal"
    TOKEN = "token"
    COMPLIANCE = "compliance"


class DocumentType(str, PyEnum):
    OPERATING_AGREEMENT = "operating_agreement"
    OFFERING_MEMORANDUM = "offering_memorandum"
    SUBSCRIPTION = "subscription"
    KYC = "kyc"
    AUDIT_REPORT = "audit_report"
    OTHER = "other"


class DocumentSignatureState(str, PyEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"


class Document(PrimaryKeyUUIDMixin, TimestampMixin, Base):
    __tablename__ = "documents"

    entity_type: Mapped[DocumentEntityType] = mapped_column(
        SAEnum(DocumentEntityType, name="documententitytype", native_enum=False)
    )
    entity_id: Mapped[Any] = mapped_column(GUID(), nullable=False)
    token_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    document_type: Mapped[DocumentType] = mapped_column(
        SAEnum(DocumentType, name="documenttype", native_enum=False)
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    storage_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    storage_version_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    sha256_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    hash_verified_at: Mapped[datetime | None] = mapped_column(nullable=True)

    status: Mapped[DocumentStatus] = mapped_column(
        SAEnum(DocumentStatus, name="documentstatus", native_enum=False),
        nullable=False,
        default=DocumentStatus.UPLOADED,
    )
    on_chain_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)

    uploaded_by: Mapped[Any] = mapped_column(GUID(), nullable=False)
    verified_by: Mapped[Any | None] = mapped_column(GUID(), nullable=True)
    archived_by: Mapped[Any | None] = mapped_column(GUID(), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(nullable=True)

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON, nullable=True)
    signatures_json: Mapped[list[dict[str, Any]] | None] = mapped_column("signatures", JSON, nullable=True)
    signature_state: Mapped[DocumentSignatureState | None] = mapped_column(
        SAEnum(DocumentSignatureState, name="documentsignaturestate", native_enum=False), nullable=True
    )
    signature_envelope_id: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=False)



class DocumentAuditEvent(str, PyEnum):
    UPLOAD = "document.uploaded"
    VERIFIED = "document.verified"
    MISMATCH = "document.mismatch"
    ARCHIVED = "document.archived"
    RELINKED = "document.relinked"
    REHASH_REQUESTED = "document.rehash_requested"
    SIGNATURE_REQUESTED = "document.signature_requested"
    SIGNATURE_COMPLETED = "document.signature_completed"
