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
    assert result["password"]
    assert result["uploadUrls"][0]["upload"]["headers"]["x-amz-server-side-encryption"] == "aws:kms"
    assert repo.get(result["shareId"]).password_hash != result["password"]
    assert mailer.sent_messages[0]["type"] == "access_link"


def test_download_requires_matching_email_password_and_otp():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, repo, mailer, _ = build_service(now)
    share = service.create_share(
        recipient_email="recipient@example.com",
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )

    service.request_otp(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
    )
    session = repo.get(share["shareId"])
    otp_code = session.otp_code

    download = service.authorize_download(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
        otp_code=otp_code,
    )

    assert download["objectKey"] == f"temp/{share['shareId']}.zip"
    assert download["expiresIn"] == 300
    assert mailer.sent_messages[1]["type"] == "otp"


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
            password=share["password"],
        )
    except ValueError as exc:
        assert str(exc) == "Share has expired"
    else:
        raise AssertionError("Expected expired share to be rejected")


def test_share_denies_second_download_after_success():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service, repo, _, _ = build_service(now)
    share = service.create_share(
        recipient_email="recipient@example.com",
        files=[{"path": "folder/file.txt", "size_bytes": 12, "content_type": "text/plain"}],
    )
    service.request_otp(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
    )
    otp_code = repo.get(share["shareId"]).otp_code
    service.authorize_download(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
        otp_code=otp_code,
    )

    service.request_otp(
        share_id=share["shareId"],
        recipient_email="recipient@example.com",
        password=share["password"],
    )
    second_otp = repo.get(share["shareId"]).otp_code

    try:
        service.authorize_download(
            share_id=share["shareId"],
            recipient_email="recipient@example.com",
            password=share["password"],
            otp_code=second_otp,
        )
    except ValueError as exc:
        assert str(exc) == "Download no longer available"
    else:
        raise AssertionError("Expected second download to be rejected")
