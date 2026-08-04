from __future__ import annotations

from app.service import InMemoryRepository, ShareService


repository = InMemoryRepository()
service = ShareService(repository=repository)


def create_share(payload: dict) -> dict:
    return service.create_share(
        recipient_email=payload["recipientEmail"],
        files=payload["files"],
        ttl_seconds=payload.get("ttlSeconds"),
        password=payload.get("password"),
    )


def request_share_otp(payload: dict) -> dict:
    return service.request_otp(
        share_id=payload["shareId"],
        recipient_email=payload["recipientEmail"],
        password=payload.get("password", ""),
    )


def authorize_share_download(payload: dict) -> dict:
    return service.authorize_download(
        share_id=payload["shareId"],
        recipient_email=payload["recipientEmail"],
        password=payload.get("password", ""),
        otp_code=payload["otpCode"],
    )


def expire_share(share_id: str) -> None:
    service.expire_share(share_id=share_id)
