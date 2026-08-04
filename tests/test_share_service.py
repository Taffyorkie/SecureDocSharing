from datetime import UTC, datetime, timedelta

from app.service import InMemoryRepository, NoopMailer, ShareService


def build_service(now: datetime):
    current = {"now": now}

    def now_factory():
        return current["now"]

    repo = InMemoryRepository()
    mailer = NoopMailer()
    service = ShareService(repository=repo, mailer=mailer, now_factory=now_factory)
    return service, repo, mailer, current


def test_create_share_sets_one_hour_expiry_and_upload_controls():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, repo, mailer, _ = build_service(now)

    result = service.create_share(
        recipient_email="Recipient@Example.com ",
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )

    assert result["recipientEmail"] == "recipient@example.com"
    assert result["expiresAt"] == (now + timedelta(hours=1)).isoformat()
    assert result["pin"]
    assert result["uploadUrls"][0]["upload"]["headers"]["x-amz-server-side-encryption"] == "aws:kms"
    assert repo.get(result["shareId"]).password_hash is None
    assert mailer.sent_messages[0]["type"] == "access_link"


def test_download_requires_matching_email_optional_password_and_pin():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, repo, mailer, _ = build_service(now)
    share = service.create_share(
        recipient_email="recipient@example.com",
        password="S3cret!",
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )

    download = service.authorize_download(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
        otp_code=share["pin"],
    )

    assert download["objectKey"] == f"temp/{share['shareId']}.zip"
    assert download["expiresIn"] == 300
    assert repo.get(share["shareId"]) is None


def test_share_denies_access_after_one_hour_expiry():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, _, _, clock = build_service(now)
    share = service.create_share(
        recipient_email="recipient@example.com",
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )

    clock["now"] = now + timedelta(hours=1, seconds=1)

    try:
        service.request_otp(
            share_id=share["shareId"],
            recipient_email="recipient@example.com",
            password="",
        )
    except ValueError as exc:
        assert str(exc) == "Share has expired"
    else:
        raise AssertionError("Expected expired share to be rejected")


def test_share_uses_custom_ttl_and_passwordless_downloads():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, repo, _, _ = build_service(now)
    share = service.create_share(
        recipient_email="recipient@example.com",
        ttl_seconds=90,
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )

    assert share["ttlSeconds"] == 90
    assert share["expiresAt"] == (now + timedelta(seconds=90)).isoformat()

    service.authorize_download(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password="",
        otp_code=share["pin"],
    )

    assert repo.get(share["shareId"]) is None

def test_share_rejects_invalid_ttl():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, _, _, _ = build_service(now)

    try:
        service.create_share(
            recipient_email="recipient@example.com",
            ttl_seconds=0,
            files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
        )
    except ValueError as exc:
        assert str(exc) == "TTL is not valid"
    else:
        raise AssertionError("Expected invalid TTL to be rejected")
