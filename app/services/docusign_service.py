from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass

from docusign_esign import ApiClient, Document as DSDocument, EnvelopeDefinition, EnvelopesApi, Recipients, SignHere, Signer, Tabs
from docusign_esign.client.api_exception import ApiException

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="DocuSignService")


class DocuSignConfigurationError(Exception):
    """Raised when DocuSign is not configured correctly."""


class DocuSignConsentRequiredError(Exception):
    """Raised when user consent is required for JWT authentication."""
    
    def __init__(self, consent_url: str) -> None:
        self.consent_url = consent_url
        super().__init__(
            f"DocuSign user consent is required. Please visit the following URL to grant consent:\n{consent_url}\n"
            f"After granting consent, the integration will work automatically."
        )


@dataclass
class DocuSignRecipient:
    email: str
    name: str
    routing_order: int


class DocuSignService:
    """Thin wrapper around the DocuSign SDK."""

    _SCOPES = ["signature", "impersonation"]

    def __init__(self) -> None:
        base_path = str(settings.docusign_base_path).rstrip("/") if settings.docusign_base_path else None
        # Ensure base_path includes /restapi if not already present
        if base_path and "/restapi" not in base_path:
            base_path = f"{base_path}/restapi"
        self._base_path = base_path
        self._account_id = settings.docusign_account_id
        self._integration_key = settings.docusign_integration_key
        self._user_id = settings.docusign_user_id
        self._oauth_base_path = settings.docusign_oauth_base_path or "account.docusign.com"
        self._private_key = settings.docusign_private_key
        self._redirect_uri = settings.docusign_redirect_uri or "https://developers.docusign.com/platform/auth/consent"

    def _ensure_configured(self) -> None:
        missing = [
            self._base_path,
            self._account_id,
            self._integration_key,
            self._user_id,
            self._private_key,
        ]
        if any(value in (None, "") for value in missing):
            raise DocuSignConfigurationError("DocuSign credentials are not fully configured")

    def _get_consent_url(self) -> str:
        """Generate the consent URL for user to grant permission."""
        from urllib.parse import urlencode
        
        url_scopes = "+".join(self._SCOPES)
        # Build query parameters
        params = {
            "response_type": "code",
            "scope": url_scopes,
            "client_id": self._integration_key,
            "redirect_uri": self._redirect_uri,  # urlencode will handle encoding
        }
        consent_url = f"https://{self._oauth_base_path}/oauth/auth?{urlencode(params)}"
        return consent_url

    def _get_jwt_token(self) -> str:
        """Get JWT access token from DocuSign."""
        self._ensure_configured()
        api_client = ApiClient()
        api_client.set_base_path(self._oauth_base_path)
        api_client.set_oauth_host_name(self._oauth_base_path)
        
        private_key_bytes = self._private_key.encode("ascii")
        try:
            token_response = api_client.request_jwt_user_token(
                client_id=self._integration_key,
                user_id=self._user_id,
                oauth_host_name=self._oauth_base_path,
                private_key_bytes=private_key_bytes,
                expires_in=3600,
                scopes=self._SCOPES,
            )
            return token_response.access_token
        except ApiException as exc:
            # Check if consent is required
            error_body = exc.body.decode("utf-8") if exc.body else ""
            if "consent_required" in error_body.lower():
                consent_url = self._get_consent_url()
                logger.error(
                    "DocuSign consent required",
                    consent_url=consent_url,
                    integration_key=self._integration_key,
                    user_id=self._user_id,
                )
                raise DocuSignConsentRequiredError(consent_url) from exc
            # Re-raise other API exceptions
            raise

    def _build_api_client(self) -> ApiClient:
        """Create and configure API client with JWT authentication."""
        access_token = self._get_jwt_token()
        
        api_client = ApiClient()
        api_client.host = self._base_path
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        return api_client

    async def create_envelope(
        self,
        *,
        document_id: str,
        document_name: str,
        document_bytes: bytes,
        signers: list[DocuSignRecipient],
        email_subject: str,
        email_body: str | None = None,
    ) -> tuple[str, dict[str, str]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._create_envelope_sync,
            document_id,
            document_name,
            document_bytes,
            signers,
            email_subject,
            email_body,
        )

    def _create_envelope_sync(
        self,
        document_id: str,
        document_name: str,
        document_bytes: bytes,
        signers: list[DocuSignRecipient],
        email_subject: str,
        email_body: str | None,
    ) -> tuple[str, dict[str, str]]:
        api_client = self._build_api_client()
        envelopes_api = EnvelopesApi(api_client)

        document_base64 = base64.b64encode(document_bytes).decode("utf-8")
        ds_document = DSDocument(
            document_base64=document_base64,
            name=document_name,
            file_extension=document_name.split(".")[-1] if "." in document_name else "pdf",
            document_id="1",
        )

        ds_signers: list[Signer] = []
        recipient_map: dict[str, str] = {}
        for idx, recipient in enumerate(signers, start=1):
            recipient_id = str(idx)
            ds_signers.append(
                Signer(
                    email=recipient.email,
                    name=recipient.name,
                    recipient_id=recipient_id,
                    routing_order=str(recipient.routing_order or idx),
                    tabs=Tabs(
                        sign_here_tabs=[
                            SignHere(
                                document_id="1",
                                page_number="1",
                                x_position="100",
                                y_position="150",
                            )
                        ]
                    ),
                )
            )
            recipient_map[recipient.email] = recipient_id

        envelope_definition = EnvelopeDefinition(
            email_subject=email_subject,
            email_blurb=email_body,
            documents=[ds_document],
            recipients=Recipients(signers=ds_signers),
            status="sent",
        )

        try:
            response = envelopes_api.create_envelope(account_id=self._account_id, envelope_definition=envelope_definition)
        except ApiException as exc:
            logger.exception("DocuSign envelope creation failed", document_id=document_id, error=str(exc))
            raise

        envelope_id = response.envelope_id
        logger.info("DocuSign envelope created", envelope_id=envelope_id, document_id=document_id)
        return envelope_id, recipient_map

    async def download_completed_document(
        self,
        *,
        envelope_id: str,
        document_id: str = "combined",
    ) -> bytes:
        """
        Download the completed signed document from DocuSign.
        
        Args:
            envelope_id: DocuSign envelope ID
            document_id: Document ID to download. Use "combined" for the final merged PDF with all signatures.
        
        Returns:
            Document bytes (typically PDF)
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._download_completed_document_sync,
            envelope_id,
            document_id,
        )

    def _download_completed_document_sync(
        self,
        envelope_id: str,
        document_id: str,
    ) -> bytes:
        """Synchronous implementation of document download."""
        api_client = self._build_api_client()
        envelopes_api = EnvelopesApi(api_client)

        try:
            # Download the document
            # Use "combined" to get the final merged PDF with all signatures
            document = envelopes_api.get_document(
                account_id=self._account_id,
                envelope_id=envelope_id,
                document_id=document_id,
            )
            # The document is returned as a file-like object
            document_bytes = document.read()
            logger.info(
                "Downloaded signed document from DocuSign",
                envelope_id=envelope_id,
                document_id=document_id,
                size_bytes=len(document_bytes),
            )
            return document_bytes
        except ApiException as exc:
            logger.exception(
                "Failed to download signed document from DocuSign",
                envelope_id=envelope_id,
                document_id=document_id,
                error=str(exc),
            )
            raise
