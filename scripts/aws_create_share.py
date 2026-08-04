from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from io import BytesIO
import json
import mimetypes
from pathlib import Path
import secrets
import zipfile

import boto3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a secure file share in the deployed AWS proxy")
    parser.add_argument("--region", required=True)
    parser.add_argument("--recipient-email", required=True)
    parser.add_argument("--ttl-seconds", type=int, required=True)
    parser.add_argument("--password", default="")
    parser.add_argument("--folder", required=True)
    parser.add_argument("--proxy-config-json", required=True)
    parser.add_argument("--result-json", required=True)
    return parser.parse_args()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_secret(secret_text: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac("sha256", secret_text.encode("utf-8"), bytes.fromhex(salt), 600_000).hex()
    return salt, derived


def make_zip(folder: Path) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                arcname = path.relative_to(folder.parent).as_posix()
                archive.write(path, arcname=arcname)
    return buffer.getvalue()


def collect_content_summary(folder: Path) -> list[dict]:
    files: list[dict] = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue
        files.append(
            {
                "path": path.relative_to(folder.parent).as_posix(),
                "sizeBytes": path.stat().st_size,
                "contentType": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            }
        )
    return files


def ensure_valid_ttl(ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be greater than zero")
    if ttl_seconds > 604800:
        raise ValueError("ttl_seconds cannot exceed 604800 seconds (7 days)")


def main() -> None:
    args = parse_args()
    ensure_valid_ttl(args.ttl_seconds)

    folder = Path(args.folder).resolve()
    if not folder.exists() or not folder.is_dir():
        raise ValueError("folder must point to an existing directory")

    files = collect_content_summary(folder)
    if not files:
        raise ValueError("folder is empty")

    proxy_config = json.loads(Path(args.proxy_config_json).read_text(encoding="utf-8"))

    recipient_email = normalize_email(args.recipient_email)
    password = args.password.strip()
    share_id = secrets.token_hex(16)
    pin = f"{secrets.randbelow(1_000_000):06d}"
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=args.ttl_seconds)
    expires_epoch = int(expires_at.timestamp())

    password_salt = ""
    password_hash = ""
    if password:
        password_salt, password_hash = hash_secret(password)

    pin_salt, pin_hash = hash_secret(pin)

    s3_key = f"shares/{share_id}/payload.zip"
    zip_bytes = make_zip(folder)

    session = boto3.Session(region_name=args.region)
    s3_client = session.client("s3")
    table = session.resource("dynamodb").Table(proxy_config["tableName"])

    s3_client.put_object(
        Bucket=proxy_config["bucketName"],
        Key=s3_key,
        Body=zip_bytes,
        ContentType="application/zip",
        ServerSideEncryption="AES256",
    )

    item = {
        "shareId": share_id,
        "status": "active",
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "expiresAtEpoch": expires_epoch,
        "ttlSeconds": args.ttl_seconds,
        "recipientEmailHash": hash_text(recipient_email),
        "passwordSalt": password_salt,
        "passwordHash": password_hash,
        "pinSalt": pin_salt,
        "pinHash": pin_hash,
        "s3Key": s3_key,
        "fileName": f"{folder.name}.zip",
        "fileCount": len(files),
    }
    table.put_item(Item=item)

    share_url = f"{proxy_config['functionUrl'].rstrip('/')}/shares/{share_id}"
    result = {
        "shareId": share_id,
        "shareUrl": share_url,
        "pin": pin,
        "recipientEmail": recipient_email,
        "expiresAt": expires_at.isoformat(),
        "passwordProtected": bool(password),
        "fileCount": len(files),
        "approxSizeBytes": int(sum(entry["sizeBytes"] for entry in files)),
    }
    Path(args.result_json).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()