from __future__ import annotations

import argparse
from base64 import b64encode
from io import BytesIO
import json
import mimetypes
import os
from pathlib import Path
import shutil
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an encrypted static share site")
    parser.add_argument("--recipient-email", required=True)
    parser.add_argument("--ttl-seconds", type=int, required=True)
    parser.add_argument("--password", default="")
    parser.add_argument("--folder", required=True)
    parser.add_argument("--site-root", required=True)
    parser.add_argument("--public-base-url", required=True)
    parser.add_argument("--result-json", required=True)
    return parser.parse_args()


def collect_files(folder: Path) -> list[dict]:
    files: list[dict] = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(folder.parent).as_posix()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        files.append(
            {
                "path": relative_path,
                "size_bytes": path.stat().st_size,
                "content_type": content_type,
            }
        )
    if not files:
        raise ValueError("The selected folder does not contain any files")
    return files


def build_zip(folder: Path) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(folder.parent).as_posix())
    return buffer.getvalue()


def derive_key(*, recipient_email: str, password: str, pin: str, share_id: str, salt: bytes) -> bytes:
    key_material = f"{recipient_email}\n{password}\n{pin}\n{share_id}".encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(key_material)


def copy_web_assets(*, web_root: Path, site_root: Path, share_id: str) -> None:
    assets_dir = site_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(web_root / "share.css", assets_dir / "share.css")
    shutil.copy2(web_root / "share.js", assets_dir / "share.js")
    shutil.copy2(web_root / "index.html", site_root / "index.html")

    share_dir = site_root / "shares" / share_id
    share_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(web_root / "share.html", share_dir / "index.html")


def main() -> None:
    args = parse_args()
    folder = Path(args.folder).resolve()
    if not folder.exists() or not folder.is_dir():
        raise ValueError("The selected folder path is not a directory")

    os.environ["PUBLIC_SHARE_BASE_URL"] = args.public_base_url.rstrip("/")

    from app.service import InMemoryRepository, ShareService

    site_root = Path(args.site_root).resolve()
    site_root.mkdir(parents=True, exist_ok=True)

    files = collect_files(folder)
    zip_bytes = build_zip(folder)

    service = ShareService(repository=InMemoryRepository())
    share = service.create_share(
        recipient_email=args.recipient_email,
        files=files,
        ttl_seconds=args.ttl_seconds,
        password=args.password or None,
    )

    recipient_email = share["recipientEmail"]
    password = share["password"] or ""
    pin = share["pin"]
    share_id = share["shareId"]
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(recipient_email=recipient_email, password=password, pin=pin, share_id=share_id, salt=salt)
    encrypted_zip = AESGCM(key).encrypt(nonce, zip_bytes, share_id.encode("utf-8"))

    web_root = Path(__file__).resolve().parent.parent / "web"
    copy_web_assets(web_root=web_root, site_root=site_root, share_id=share_id)

    share_manifest = {
        "shareId": share_id,
        "shareUrl": share["shareUrl"],
        "recipientEmailHash": service._hash_email(recipient_email),
        "expiresAt": share["expiresAt"],
        "requiresPassword": bool(password),
        "kdf": {
            "name": "PBKDF2",
            "hash": "SHA-256",
            "iterations": 600000,
            "salt": b64encode(salt).decode("ascii"),
        },
        "cipher": {
            "name": "AES-GCM",
            "nonce": b64encode(nonce).decode("ascii"),
            "ciphertext": b64encode(encrypted_zip).decode("ascii"),
            "associatedData": b64encode(share_id.encode("utf-8")).decode("ascii"),
        },
        "downloadFileName": f"{folder.name}.zip",
        "folderName": folder.name,
    }

    share_json_path = site_root / "shares" / share_id / "share.json"
    share_json_path.write_text(json.dumps(share_manifest, indent=2), encoding="utf-8")

    result = {
        "shareId": share_id,
        "shareUrl": share["shareUrl"],
        "recipientEmail": recipient_email,
        "expiresAt": share["expiresAt"],
        "pin": pin,
        "passwordProtected": bool(password),
        "downloadFileName": share_manifest["downloadFileName"],
    }
    Path(args.result_json).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()