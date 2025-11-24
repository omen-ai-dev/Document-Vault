from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="UserDirectoryService")


class UserDirectoryError(Exception):
    """Base error for user directory lookups."""


class UserNotFoundError(UserDirectoryError):
    """Raised when a requested user does not exist."""


class UserDirectoryService:
    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._client = http_client
        # AnyHttpUrl values come through as Pydantic Url objects, so coerce to str before string ops
        if settings.user_directory_base_url:
            self._base_url = str(settings.user_directory_base_url).rstrip("/")
        else:
            self._base_url = None
        self._api_key = settings.user_directory_api_key

    def _ensure_configured(self) -> None:
        if not self._base_url:
            raise UserDirectoryError("USER_DIRECTORY_BASE_URL is not configured")

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def get_user(self, user_id: UUID) -> dict[str, Any]:
        self._ensure_configured()
        url = f"{self._base_url}/api/v1/users/{user_id}"
        response = await self._client.get(url, headers=self._headers())
        if response.status_code == 404:
            raise UserNotFoundError(f"User {user_id} not found")
        response.raise_for_status()
        payload = response.json()
        logger.debug("User directory lookup by id", user_id=str(user_id))
        return payload

    async def get_user_by_email(self, email: str) -> dict[str, Any]:
        self._ensure_configured()
        url = f"{self._base_url}/api/v1/users/search"
        response = await self._client.get(url, params={"email": email}, headers=self._headers())
        if response.status_code == 404:
            raise UserNotFoundError(f"User with email {email} not found")
        response.raise_for_status()
        payload = response.json()
        logger.debug("User directory lookup by email", email=email)
        return payload
