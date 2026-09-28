"""Object storage for raw EML and attachments (ТЗ 5 MSP-CORE-04, 26.1).

Content is stored apart from metadata with a stricter ACL. Storage keys are derived from content
hashes — never from user input — so a crafted filename cannot escape the prefix (ТЗ 30).
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import date
from io import BytesIO
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

_SAFE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9/_.\-]{0,500}$")


class StorageError(RuntimeError):
    pass


def build_key(category: str, digest: str, *, organization_id: str, extension: str = "bin") -> str:
    """Deterministic, traversal-proof key: category/org/YYYY/MM/DD/<sha256>.<ext>."""
    if category not in {"eml", "attachment", "body", "export", "report"}:
        raise ValueError(f"unknown storage category: {category}")
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        raise ValueError("digest must be a hex sha256")
    org = re.sub(r"[^a-z0-9\-]", "", (organization_id or "default").lower())[:32] or "default"
    ext = re.sub(r"[^a-z0-9]", "", (extension or "bin").lower())[:8] or "bin"
    today = date.today()
    return f"{category}/{org}/{today:%Y/%m/%d}/{digest}.{ext}"


def validate_key(key: str) -> str:
    if not key or not _SAFE_KEY_RE.match(key) or ".." in key:
        raise ValueError("invalid storage key")
    return key


class ObjectStorage(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> bool: ...
    def exists(self, key: str) -> bool: ...
    def health(self) -> tuple[bool, str]: ...


@dataclass
class FilesystemObjectStorage:
    """Local-filesystem backend for development and single-node pilots."""

    root: str

    def _path(self, key: str) -> Path:
        validate_key(key)
        base = Path(self.root).resolve()
        target = (base / key).resolve()
        # Defence in depth: the resolved path must stay inside the root.
        if not str(target).startswith(str(base)):
            raise StorageError("resolved path escapes the storage root")
        return target

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        return key

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.is_file():
            raise StorageError(f"object not found: {key}")
        return path.read_bytes()

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if path.is_file():
            path.unlink()
            return True
        return False

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def health(self) -> tuple[bool, str]:
        try:
            base = Path(self.root)
            base.mkdir(parents=True, exist_ok=True)
            probe = base / ".healthcheck"
            probe.write_bytes(b"ok")
            probe.unlink()
            return True, "filesystem storage writable"
        except OSError as exc:
            return False, f"{type(exc).__name__}"


class S3ObjectStorage:
    """S3-compatible backend (MinIO for the pilot, ТЗ 5)."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        *,
        secure: bool = False,
        region: str | None = None,
    ) -> None:
        from minio import Minio

        host = endpoint.replace("https://", "").replace("http://", "").rstrip("/")
        self.bucket = bucket
        self._client = Minio(host, access_key=access_key, secret_key=secret_key, secure=secure, region=region)
        self._ensured = False

    def _ensure_bucket(self) -> None:
        if self._ensured:
            return
        if not self._client.bucket_exists(self.bucket):
            self._client.make_bucket(self.bucket)
        self._ensured = True

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        validate_key(key)
        self._ensure_bucket()
        self._client.put_object(self.bucket, key, BytesIO(data), length=len(data), content_type=content_type)
        return key

    def get(self, key: str) -> bytes:
        validate_key(key)
        response = None
        try:
            response = self._client.get_object(self.bucket, key)
            return response.read()
        except Exception as exc:
            raise StorageError(f"object not readable: {key}") from exc
        finally:
            if response is not None:
                response.close()
                response.release_conn()

    def delete(self, key: str) -> bool:
        validate_key(key)
        try:
            self._client.remove_object(self.bucket, key)
            return True
        except Exception:  # noqa: BLE001
            return False

    def exists(self, key: str) -> bool:
        validate_key(key)
        try:
            self._client.stat_object(self.bucket, key)
            return True
        except Exception:  # noqa: BLE001
            return False

    def health(self) -> tuple[bool, str]:
        try:
            self._ensure_bucket()
            return True, f"bucket '{self.bucket}' reachable"
        except Exception as exc:  # noqa: BLE001
            return False, type(exc).__name__


def build_storage(settings) -> ObjectStorage:  # type: ignore[no-untyped-def]
    if settings.object_storage_backend == "filesystem":
        return FilesystemObjectStorage(settings.object_storage_path)
    return S3ObjectStorage(
        settings.object_storage_endpoint,
        settings.object_storage_access_key,
        settings.object_storage_secret_key,
        settings.object_storage_bucket,
        secure=settings.object_storage_secure,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
