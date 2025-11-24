from __future__ import annotations

from collections.abc import AsyncIterator
from typing import BinaryIO
from uuid import uuid4

import aioboto3
from botocore.config import Config

from app.core.config import settings


class StorageService:
    CHUNK_SIZE = 1024 * 1024

    def __init__(self) -> None:
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            raise RuntimeError("AWS access key id and secret access key must be configured.")

        self._session = aioboto3.Session(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            aws_session_token=settings.aws_session_token,
            region_name=settings.aws_region,
        )

    async def upload_document(self, file_obj: BinaryIO, *, filename: str, mime_type: str) -> tuple[str, str | None]:
        object_key = f"documents/{uuid4()}/{filename}"
        file_obj.seek(0)
        file_obj.seek(0)
        body = file_obj.read()
        async with self._session.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(signature_version="s3v4"),
        ) as s3_client:
            await s3_client.put_object(
                Bucket=settings.document_bucket,
                Key=object_key,
                Body=body,
                ContentType=mime_type,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=settings.s3_kms_key_id,
            )
            head_object = await s3_client.head_object(Bucket=settings.document_bucket, Key=object_key)

        version_id = head_object.get("VersionId")
        return object_key, version_id

    async def stream_document(self, storage_key: str) -> AsyncIterator[bytes]:
        async with self._session.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(signature_version="s3v4"),
        ) as s3_client:
            response = await s3_client.get_object(Bucket=settings.document_bucket, Key=storage_key)
            async for chunk in response["Body"].iter_chunks(chunk_size=self.CHUNK_SIZE):
                yield chunk

    async def generate_presigned_url(self, storage_key: str, expires_in_seconds: int) -> str:
        async with self._session.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(signature_version="s3v4"),
        ) as s3_client:
            return await s3_client.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": settings.document_bucket, "Key": storage_key},
                ExpiresIn=expires_in_seconds,
            )

    async def download_document_bytes(self, storage_key: str) -> bytes:
        async with self._session.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(signature_version="s3v4"),
        ) as s3_client:
            response = await s3_client.get_object(Bucket=settings.document_bucket, Key=storage_key)
            body = response["Body"]
            data = await body.read()
            return data
