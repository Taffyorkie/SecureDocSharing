from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ShareFile:
    path: str
    size_bytes: int
    content_type: str


@dataclass
class ShareSession:
    share_id: str
    recipient_email: str
    recipient_email_hash: str
    password_hash: str | None
    password_salt: str | None
    access_pin_hash: str
    access_pin_salt: str
    expires_at: datetime
    created_at: datetime
    files: list[ShareFile]
    upload_prefix: str
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    status: str = "active"
    verified_at: datetime | None = None
    otp_code: str | None = None
    otp_expires_at: datetime | None = None
    download_count: int = 0
    max_downloads: int = 1
