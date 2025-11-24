from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, status, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_document_service, get_document_signature_service
from app.core.config import settings
from app.core.logger import get_logger
from app.db.session import get_db_session
from app.models.document import DocumentEntityType, DocumentSignatureState, DocumentType
from app.schemas.document import (
    DocumentDeleteResponse,
    DocumentDownloadResponse,
    DocumentListResponse,
    DocumentMetadata,
    DocumentResponse,
    DocumentRelinkRequest,
    DocumentSignatureRequest,
    DocumentUploadMetadata,
    DocumentVerifyRequest,
)
from app.services.document_service import DocumentNotFoundError, DocumentService
from app.services.document_signature_service import DocumentSignatureService, SignatureOperationError

router = APIRouter(prefix="/documents", tags=["documents"])
logger = get_logger(component="DocumentRoutes")


@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    entity_id: UUID = Form(...),
    entity_type: DocumentEntityType = Form(...),
    document_type: DocumentType = Form(...),
    uploaded_by: UUID = Form(...),
    token_id: int | None = Form(default=None),
    metadata: str | None = Form(default=None),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        metadata_payload = DocumentMetadata.model_validate(json.loads(metadata)) if metadata else None
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="metadata must be valid JSON") from exc

    upload_metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=entity_type,
        document_type=document_type,
        uploaded_by=uploaded_by,
        token_id=token_id,
        metadata=metadata_payload,
    )

    try:
        document = await document_service.upload_document(session, file=file, metadata=upload_metadata)
        await session.commit()
        return DocumentResponse.from_model(document)
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.post("/verify", response_model=DocumentResponse)
async def verify_document(
    payload: DocumentVerifyRequest,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.verify_document(
            session, document_id=payload.document_id, verifier_id=payload.verifier_id
        )
        await session.flush()
        await session.commit()
        if hasattr(document, "_sa_instance_state"):
            await session.refresh(document)
        return DocumentResponse.from_model(document)
    except DocumentNotFoundError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.get("/{entity_id}", response_model=DocumentListResponse)
async def list_documents(
    entity_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    documents = await document_service.list_documents(session, entity_id=entity_id)
    return DocumentListResponse(documents=[DocumentResponse.from_model(doc) for doc in documents])


@router.get("/{document_id}/download", response_model=DocumentDownloadResponse)
async def generate_download_url(
    document_id: UUID,
    requestor_id: UUID = Query(...),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document, url = await document_service.generate_download_url(
            session, document_id=document_id, requestor_id=requestor_id
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return DocumentDownloadResponse(
        document_id=document.id,
        download_url=url,
        expires_in_seconds=settings.presigned_url_expiration_seconds,
    )


@router.post("/{document_id}/relink", response_model=DocumentResponse)
async def relink_document(
    document_id: UUID,
    payload: DocumentRelinkRequest,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.relink_document(
            session,
            document_id=document_id,
            new_entity_id=payload.new_entity_id,
            new_entity_type=payload.new_entity_type,
            relinked_by=payload.relinked_by,
            token_id=payload.token_id,
        )
        await session.commit()
        return DocumentResponse.from_model(document)
    except DocumentNotFoundError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.delete("/{document_id}", response_model=DocumentDeleteResponse)
async def archive_document(
    document_id: UUID,
    archived_by: UUID = Query(...),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.archive_document(
            session, document_id=document_id, archived_by=archived_by
        )
        await session.commit()
        return DocumentDeleteResponse(
            document_id=document.id,
            status=document.status,
            archived_at=document.archived_at,
        )
    except DocumentNotFoundError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.post("/{document_id}/signatures/request", response_model=DocumentResponse)
async def request_document_signatures(
    document_id: UUID,
    payload: DocumentSignatureRequest,
    session: AsyncSession = Depends(get_db_session),
    signature_service: DocumentSignatureService = Depends(get_document_signature_service),
):
    try:
        document = await signature_service.request_signatures(
            session,
            document_id=document_id,
            payload=payload,
            requested_by=payload.requested_by,
        )
        await session.commit()
        if hasattr(document, "_sa_instance_state"):
            await session.refresh(document)
        return DocumentResponse.from_model(document)
    except (DocumentNotFoundError, SignatureOperationError) as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.get("/{document_id}/signatures/status", response_model=DocumentResponse)
async def get_signature_status(
    document_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.get_document(session, document_id)
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return DocumentResponse.from_model(document)


@router.get("/{document_id}/signatures/signed-document")
async def download_signed_document(
    document_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
    signature_service: DocumentSignatureService = Depends(get_document_signature_service),
):
    """
    Download the signed document from DocuSign.
    Only available for documents with completed signatures.
    """
    try:
        document = await document_service.get_document(session, document_id)
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if not document.signature_envelope_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document does not have a DocuSign envelope",
        )

    if document.signature_state != DocumentSignatureState.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Document signatures are not completed. Current state: {document.signature_state}",
        )

    try:
        signed_document_bytes = await signature_service.download_signed_document(
            envelope_id=document.signature_envelope_id,
        )
    except Exception as exc:
        logger.exception("Failed to download signed document", document_id=str(document_id), error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download signed document from DocuSign",
        ) from exc

    # Return the PDF with appropriate headers
    from fastapi.responses import Response

    return Response(
        content=signed_document_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="signed_{document.filename}"',
        },
    )


@router.post("/signatures/webhook/docusign", status_code=status.HTTP_202_ACCEPTED)
async def docusign_webhook(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    signature_service: DocumentSignatureService = Depends(get_document_signature_service),
):
    payload = await request.json()
    envelope_id = payload.get("envelopeId") or payload.get("EnvelopeID")
    recipients_section = payload.get("recipients") or payload.get("Recipients") or {}
    recipient_updates = recipients_section.get("signers") or recipients_section.get("Signers") or []
    if not envelope_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Envelope ID missing in webhook payload")

    await signature_service.process_webhook_notification(session, envelope_id, recipient_updates)
    await session.commit()
    return {"status": "accepted"}
