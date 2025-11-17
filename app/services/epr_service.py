from __future__ import annotations

import json
from uuid import UUID

import httpx

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="EprService")


class EprService:
    """
    Client for the Entity & Permissions Core (EPR) service.
    
    This service handles authorization checks by making HTTP calls to the EPR service.
    When EPR_MOCK_MODE is enabled, use EprServiceMock instead.
    """

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client
        if settings.epr_service_url:
            self.base_url = str(settings.epr_service_url).rstrip("/")
        else:
            self.base_url = None
        self.timeout = settings.epr_service_timeout

    async def is_authorized(
        self, *, user_id: UUID, action: str, resource_id: UUID, principal_type: str = "user"
    ) -> bool:
        """
        Check if a user is authorized to perform an action on a resource.

        Args:
            user_id: UUID of the user requesting access
            action: The action being requested (e.g., "document:upload")
            resource_id: UUID of the resource being accessed
            principal_type: Type of principal (default: "user")

        Returns:
            bool: True if authorized, False otherwise

        Raises:
            Exception: If the EPR service is unavailable or returns an error
        """
        if not self.base_url:
            logger.error("EPR service URL not configured")
            return False

        payload = {
            "user_id": str(user_id),
            "action": action,
            "resource_id": str(resource_id),
            "principal_type": principal_type,
        }

        try:
            response = await self.http_client.post(
                f"{self.base_url}/api/v1/authorize",
                json=payload,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                is_allowed = data.get("authorized", False)
                logger.info(
                    "EPR authorization check",
                    user_id=str(user_id),
                    action=action,
                    resource_id=str(resource_id),
                    allowed=is_allowed,
                )
                return is_allowed

            if response.status_code == 404:
                logger.warning(
                    "EPR authorization check failed - entity not found",
                    user_id=str(user_id),
                    action=action,
                    resource_id=str(resource_id),
                )
                return False

            logger.warning(
                "EPR service returned unexpected status",
                status_code=response.status_code,
                user_id=str(user_id),
                action=action,
                response_body=response.text,
            )
            return False

        except httpx.TimeoutException:
            logger.error(
                "EPR service timeout",
                user_id=str(user_id),
                action=action,
                timeout=self.timeout,
            )
            return False
        except httpx.RequestError as exc:
            logger.error(
                "EPR service request error",
                user_id=str(user_id),
                action=action,
                error=str(exc),
            )
            return False

    async def trigger_document_verification_workflow(
        self,
        *,
        document_id: UUID,
        entity_id: UUID,
        entity_type: str,
        document_type: str,
    ) -> None:
        """
        Trigger the document verification workflow in the EPR service.

        Args:
            document_id: UUID of the document to verify.
            entity_id: UUID of the owning entity.
            entity_type: Type of the entity (e.g., "issuer").
            document_type: Type of the document (e.g., "offering_memorandum").
        """
        if not self.base_url:
            logger.error("EPR service URL not configured, cannot trigger workflow.")
            return

        payload = {
            "document_id": str(document_id),
            "entity_id": str(entity_id),
            "entity_type": entity_type,
            "document_type": document_type,
        }

        # Helpful when debugging integration failures: emit equivalent curl command
        curl_cmd = (
            f"curl -X POST '{self.base_url}/api/v1/workflows/document-verification/trigger' "
            f"-H 'Content-Type: application/json' "
            f"-d '{json.dumps(payload)}'"
        )
        logger.info(
            "Triggering document verification workflow via EPR",
            document_id=str(document_id),
            entity_id=str(entity_id),
            curl=curl_cmd,
        )

        try:
            response = await self.http_client.post(
                f"{self.base_url}/api/v1/workflows/document-verification/trigger",
                json=payload,
                timeout=self.timeout,
            )

            if response.status_code in [200, 201, 202]:
                logger.info(
                    "Successfully triggered document verification workflow.",
                    document_id=str(document_id),
                    status_code=response.status_code,
                )
            else:
                logger.warning(
                    "Failed to trigger document verification workflow.",
                    document_id=str(document_id),
                    status_code=response.status_code,
                    response_body=response.text,
                )

        except httpx.RequestError as e:
            logger.error(
                "Error triggering document verification workflow.",
                document_id=str(document_id),
                error=str(e),
            )
