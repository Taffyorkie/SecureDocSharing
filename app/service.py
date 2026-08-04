from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
from typing import Protocol
from uuid import uuid4

from app.config import settings
from app.models import ShareFile, ShareSession


class SecretsProvider(Protocol):
    def generate_password(self, *, length: int = 24) -> str: ...


class Scheduler(Protocol):
    def schedule_cleanup(self, *, share_id: str, run_at: datetime) -> dict: ...


class Mailer(Protocol):
    def send_access_link(self, *, recipient_email: str, share_id: str, expires_at: datetime) -> None: ...
    def send_otp(self, *, recipient_email: str, otp_code: str, expires_at: datetime) -> None: ...


class Storage(Protocol):
    def create_upload_url(self, *, object_key: str, expires_in: int) -> dict: ...
    def create_download_url(self, *, object_key: str, expires_in: int) -> str: ...
    def create_zip_download(self, *, share_id: str, files: list[ShareFile], expires_in: int) -> dict: ...
    def delete_share_objects(self, *, share_id: str) -> None: ...


class InMemoryRepository:
    def __init__(self) -> None:
        self._sessions: dict[str, ShareSession] = {}

    def save(self, session: ShareSession) -> ShareSession:
        self._sessions[session.share_id] = session
        return session

    def get(self, share_id: str) -> ShareSession | None:
        return self._sessions.get(share_id)

    def delete(self, share_id: str) -> None:
        self._sessions.pop(share_id, None)


class DefaultSecretsProvider:
    def generate_password(self, *, length: int = 24) -> str:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))


class NoopScheduler:
    def schedule_cleanup(self, *, share_id: str, run_at: datetime) -> dict:
        return {"shareId": share_id, "scheduledFor": run_at.isoformat()}


class NoopMailer:
    def __init__(self) -> None:
        self.sent_messages: list[dict[str, str]] = []

    def send_access_link(self, *, recipient_email: str, share_id: str, expires_at: datetime) -> None:
        self.sent_messages.append({"type": "access_link", "recipient_email": recipient_email, "share_id": share_id, "expires_at": expires_at.isoformat()})

    def send_otp(self, *, recipient_email: str, otp_code: str, expires_at: datetime) -> None:
        self.sent_messages.append({"type": "otp", "recipient_email": recipient_email, "otp_code": otp_code, "expires_at": expires_at.isoformat()})


class NoopStorage:
    def create_upload_url(self, *, object_key: str, expires_in: int) -> dict:
        return {
            "method": "PUT",
            "url": f"https://uploads.example/{object_key}?expires={expires_in}",
            "headers": {
                "x-amz-server-side-encryption": "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id": settings.kms_key_id,
            },
        }

    def create_download_url(self, *, object_key: str, expires_in: int) -> str:
        return f"https://downloads.example/{object_key}?expires={expires_in}"

    def create_zip_download(self, *, share_id: str, files: list[ShareFile], expires_in: int) -> dict:
        return {
            "objectKey": f"temp/{share_id}.zip",
            "downloadUrl": self.create_download_url(object_key=f"temp/{share_id}.zip", expires_in=expires_in),
            "expiresIn": expires_in,
            "files": [asdict(file) for file in files],
        }

    def delete_share_objects(self, *, share_id: str) -> None:
        return None


class ShareService:
    def __init__(
        self,
        *,
        repository: InMemoryRepository,
        secrets_provider: SecretsProvider | None = None,
        scheduler: Scheduler | None = None,
        mailer: Mailer | None = None,
        storage: Storage | None = None,
        now_factory=None,
    ) -> None:
        self.repository = repository
        self.secrets_provider = secrets_provider or DefaultSecretsProvider()
        self.scheduler = scheduler or NoopScheduler()
        self.mailer = mailer or NoopMailer()
        self.storage = storage or NoopStorage()
        self.now_factory = now_factory or (lambda: datetime.now(UTC))

    def create_share(self, *, recipient_email: str, files: list[dict], ttl_seconds: int | None = None, password: str | None = None) -> dict:
        now = self.now_factory()
        effective_ttl_seconds = ttl_seconds or settings.share_ttl_seconds
        if effective_ttl_seconds <= 0 or effective_ttl_seconds > settings.max_share_ttl_seconds:
            raise ValueError("TTL is not valid")
        expires_at = now + timedelta(seconds=effective_ttl_seconds)
        share_id = str(uuid4())
        share_password = password.strip() if password is not None else None
        if share_password == "":
            share_password = None
        if share_password is not None:
            password_salt, password_hash = self._hash_password(share_password)
        else:
            password_salt, password_hash = None, None
        access_pin = f"{secrets.randbelow(1_000_000):06d}"
        access_pin_salt, access_pin_hash = self._hash_password(access_pin)
        normalized_email = self._normalize_email(recipient_email)
        share_files = [ShareFile(**file_payload) for file_payload in files]
        upload_prefix = f"shares/{share_id}/"
        session = ShareSession(
            share_id=share_id,
            recipient_email=normalized_email,
            recipient_email_hash=self._hash_email(normalized_email),
            password_hash=password_hash,
            password_salt=password_salt,
            access_pin_hash=access_pin_hash,
            access_pin_salt=access_pin_salt,
            expires_at=expires_at,
            created_at=now,
            files=share_files,
            upload_prefix=upload_prefix,
            audit_log=[{"event": "share_created", "at": now.isoformat()}],
        )
        self.repository.save(session)
        schedule_result = self.scheduler.schedule_cleanup(share_id=share_id, run_at=expires_at)
        self.mailer.send_access_link(recipient_email=normalized_email, share_id=share_id, expires_at=expires_at)
        upload_urls = [
            {
                "path": file.path,
                "upload": self.storage.create_upload_url(
                    object_key=f"{upload_prefix}{file.path}",
                    expires_in=min(settings.download_url_ttl_seconds, effective_ttl_seconds),
                ),
            }
            for file in share_files
        ]
        return {
            "shareId": share_id,
            "shareUrl": f"{settings.public_share_base_url.rstrip('/')}/shares/{share_id}",
            "recipientEmail": normalized_email,
            "expiresAt": expires_at.isoformat(),
            "ttlSeconds": effective_ttl_seconds,
            "password": share_password,
            "pin": access_pin,
            "uploadPrefix": upload_prefix,
            "uploadUrls": upload_urls,
            "cleanupSchedule": schedule_result,
        }

    def request_otp(self, *, share_id: str, recipient_email: str, password: str) -> dict:
        session = self._require_active_session(share_id)
        normalized_email = self._normalize_email(recipient_email)
        if normalized_email != session.recipient_email:
            self._audit(session, "recipient_email_mismatch")
            raise ValueError("Recipient validation failed")
        if not self._verify_session_password(session=session, password=password):
            self._audit(session, "password_validation_failed")
            raise ValueError("Recipient validation failed")
        otp_code = f"{secrets.randbelow(1000000):06d}"
        otp_expires_at = self.now_factory() + timedelta(seconds=settings.otp_ttl_seconds)
        session.otp_code = otp_code
        session.otp_expires_at = otp_expires_at
        self._audit(session, "otp_requested")
        self.mailer.send_otp(recipient_email=session.recipient_email, otp_code=otp_code, expires_at=otp_expires_at)
        return {"shareId": share_id, "otpExpiresAt": otp_expires_at.isoformat()}

    def authorize_download(self, *, share_id: str, recipient_email: str, password: str, otp_code: str) -> dict:
        session = self._require_active_session(share_id)
        normalized_email = self._normalize_email(recipient_email)
        if normalized_email != session.recipient_email:
            self._audit(session, "recipient_email_mismatch")
            raise ValueError("Recipient validation failed")
        if not self._verify_session_password(session=session, password=password):
            self._audit(session, "password_validation_failed")
            raise ValueError("Recipient validation failed")
        now = self.now_factory()
        if session.otp_code is not None:
            if not session.otp_expires_at or now > session.otp_expires_at:
                self._audit(session, "otp_expired")
                raise ValueError("OTP validation failed")
            if not secrets.compare_digest(otp_code, session.otp_code):
                self._audit(session, "otp_validation_failed")
                raise ValueError("OTP validation failed")
        elif not self._verify_password(password=otp_code, salt=session.access_pin_salt, expected_hash=session.access_pin_hash):
            self._audit(session, "pin_validation_failed")
            raise ValueError("PIN validation failed")
        if session.download_count >= session.max_downloads:
            self._audit(session, "download_limit_reached")
            raise ValueError("Download no longer available")
        session.download_count += 1
        session.verified_at = now
        session.otp_code = None
        session.otp_expires_at = None
        self._audit(session, "download_authorized")
        download = self.storage.create_zip_download(share_id=share_id, files=session.files, expires_in=settings.download_url_ttl_seconds)
        self.storage.delete_share_objects(share_id=share_id)
        session.status = "expired"
        self._audit(session, "share_consumed")
        self.repository.delete(share_id)
        return download

    def expire_share(self, *, share_id: str) -> None:
        session = self.repository.get(share_id)
        if not session:
            return
        session.status = "expired"
        session.otp_code = None
        session.otp_expires_at = None
        self._audit(session, "share_expired")
        self.storage.delete_share_objects(share_id=share_id)
        self.repository.delete(share_id)

    def _require_active_session(self, share_id: str) -> ShareSession:
        session = self.repository.get(share_id)
        if not session or session.status != "active":
            raise ValueError("Share is not available")
        now = self.now_factory()
        if now > session.expires_at:
            session.status = "expired"
            self._audit(session, "share_expired")
            self.storage.delete_share_objects(share_id=share_id)
            self.repository.delete(share_id)
            raise ValueError("Share has expired")
        return session

    def _audit(self, session: ShareSession, event: str) -> None:
        session.audit_log.append({"event": event, "at": self.now_factory().isoformat()})

    def _normalize_email(self, email: str) -> str:
        return email.strip().lower()

    def _hash_email(self, email: str) -> str:
        return hashlib.sha256(email.encode("utf-8")).hexdigest()

    def _hash_password(self, password: str) -> tuple[str, str]:
        salt = secrets.token_hex(16)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 600_000)
        return salt, derived.hex()

    def _verify_session_password(self, *, session: ShareSession, password: str) -> bool:
        if session.password_hash is None or session.password_salt is None:
            return password.strip() == ""
        return self._verify_password(password=password, salt=session.password_salt, expected_hash=session.password_hash)

    def _verify_password(self, *, password: str, salt: str, expected_hash: str) -> bool:
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 600_000).hex()
        return hmac.compare_digest(derived, expected_hash)
