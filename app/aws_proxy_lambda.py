from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import secrets
from typing import Any

import boto3


TABLE_NAME = os.environ["SHARE_TABLE_NAME"]
BUCKET_NAME = os.environ["SHARE_BUCKET_NAME"]

ddb = boto3.resource("dynamodb")
table = ddb.Table(TABLE_NAME)
s3 = boto3.client("s3")


def _response(status_code: int, body: Any, *, headers: dict[str, str] | None = None, is_base64: bool = False) -> dict:
    merged_headers = {
        "content-type": "application/json",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type",
    }
    if headers:
        merged_headers.update(headers)
    payload = body if isinstance(body, str) else json.dumps(body)
    return {
        "statusCode": status_code,
        "headers": merged_headers,
        "body": payload,
        "isBase64Encoded": is_base64,
    }


def _html_response(status_code: int, html: str) -> dict:
    return _response(status_code, html, headers={"content-type": "text/html; charset=utf-8"})


def _now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _verify_pbkdf2(*, password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 600_000).hex()
    return hmac.compare_digest(candidate, expected_hash_hex)


def _load_share(share_id: str) -> dict[str, Any] | None:
    result = table.get_item(Key={"shareId": share_id})
    return result.get("Item")


def _is_expired(item: dict[str, Any]) -> bool:
    return int(item["expiresAtEpoch"]) <= _now_epoch()


def _cleanup_share(item: dict[str, Any]) -> None:
    s3.delete_object(Bucket=BUCKET_NAME, Key=item["s3Key"])
    table.delete_item(Key={"shareId": item["shareId"]})


def _share_page(share_id: str) -> str:
    escaped = share_id.replace("\"", "")
    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Secure Download</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Georgia, 'Times New Roman', serif; background: linear-gradient(155deg, #f3eee4, #d8e5dd); color: #172026; }}
    main {{ width: min(100%, 34rem); background: rgba(255,255,255,0.85); padding: 2rem; border-radius: 1.2rem; box-shadow: 0 18px 46px rgba(23,32,38,0.16); }}
    form {{ display: grid; gap: 0.8rem; }}
    input, button {{ font: inherit; padding: 0.8rem 0.95rem; border-radius: 0.7rem; border: 1px solid rgba(23,32,38,0.16); }}
    button {{ cursor: pointer; border: 0; color: #f8f4ea; background: linear-gradient(135deg, #19384d, #375c56); }}
    .hidden {{ display: none; }}
    .status {{ min-height: 1.2rem; color: #7f2f20; }}
  </style>
</head>
<body>
  <main id=\"access\">
    <h1>Shared folder download</h1>
    <p>Enter recipient email, password if set, and PIN.</p>
    <form id=\"form\">
      <input id=\"email\" type=\"email\" placeholder=\"Recipient email\" required />
      <input id=\"password\" type=\"password\" placeholder=\"Password (optional)\" />
      <input id=\"pin\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" placeholder=\"PIN\" required />
      <button type=\"submit\">Authenticate and download</button>
    </form>
    <p class=\"status\" id=\"status\"></p>
  </main>
  <main class=\"hidden\" id=\"complete\">
    <h2>Download complete</h2>
    <p>The share has been consumed and is no longer accessible.</p>
  </main>
  <script>
    const shareId = {json.dumps(escaped)};
    const form = document.getElementById('form');
    const statusNode = document.getElementById('status');
    const accessCard = document.getElementById('access');
    const completeCard = document.getElementById('complete');

    function setStatus(message) {{ statusNode.textContent = message; }}

    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      setStatus('Authorizing...');
      const payload = {{
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        pin: document.getElementById('pin').value,
      }};

      try {{
        const authResponse = await fetch(`/api/shares/${{shareId}}/authorize`, {{
          method: 'POST',
          headers: {{ 'content-type': 'application/json' }},
          body: JSON.stringify(payload),
        }});
        if (!authResponse.ok) {{
          throw new Error('invalid');
        }}
        const authResult = await authResponse.json();
        setStatus('Downloading...');

        const fileResponse = await fetch(authResult.downloadUrl, {{ cache: 'no-store' }});
        if (!fileResponse.ok) {{
          throw new Error('download');
        }}
        const bytes = await fileResponse.arrayBuffer();
        const blob = new Blob([bytes], {{ type: 'application/zip' }});
        const anchor = document.createElement('a');
        anchor.href = URL.createObjectURL(blob);
        anchor.download = authResult.fileName;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        await fetch(`/api/shares/${{shareId}}/complete`, {{
          method: 'POST',
          headers: {{ 'content-type': 'application/json' }},
          body: JSON.stringify({{ nonce: authResult.completeNonce }}),
        }});

        accessCard.classList.add('hidden');
        completeCard.classList.remove('hidden');
      }} catch (_error) {{
        setStatus('Access denied or share unavailable.');
      }}
    }});
  </script>
</body>
</html>"""


def _authorize(share_id: str, event: dict[str, Any]) -> dict:
    body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    payload = json.loads(body)

    item = _load_share(share_id)
    if not item:
        return _response(404, {"error": "Share not found"})
    if _is_expired(item):
        _cleanup_share(item)
        return _response(410, {"error": "Share expired"})
    if item.get("status") != "active":
        return _response(410, {"error": "Share unavailable"})

    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    pin = str(payload.get("pin", "")).strip()

    if _hash_text(email) != item["recipientEmailHash"]:
        return _response(403, {"error": "Invalid credentials"})

    if item.get("passwordHash"):
        if not _verify_pbkdf2(password=password, salt_hex=item["passwordSalt"], expected_hash_hex=item["passwordHash"]):
            return _response(403, {"error": "Invalid credentials"})
    elif password.strip() != "":
        return _response(403, {"error": "Invalid credentials"})

    if not _verify_pbkdf2(password=pin, salt_hex=item["pinSalt"], expected_hash_hex=item["pinHash"]):
        return _response(403, {"error": "Invalid credentials"})

    complete_nonce = secrets.token_urlsafe(24)
    table.update_item(
        Key={"shareId": share_id},
        UpdateExpression="SET #status = :authorized, completeNonce = :nonce, completeNonceExpiresAt = :nonce_expires",
        ConditionExpression="#status = :active",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":active": "active",
            ":authorized": "authorized",
            ":nonce": complete_nonce,
            ":nonce_expires": _now_epoch() + 600,
        },
    )

    remaining = int(item["expiresAtEpoch"]) - _now_epoch()
    expires_in = 300 if remaining > 300 else max(30, remaining)
    download_url = s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": BUCKET_NAME, "Key": item["s3Key"]},
        ExpiresIn=expires_in,
    )
    return _response(
        200,
        {
            "downloadUrl": download_url,
            "fileName": item["fileName"],
            "completeNonce": complete_nonce,
        },
    )


def _complete(share_id: str, event: dict[str, Any]) -> dict:
    body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    payload = json.loads(body)
    nonce = str(payload.get("nonce", ""))

    item = _load_share(share_id)
    if not item:
        return _response(200, {"status": "already_deleted"})

    if item.get("status") != "authorized":
        return _response(409, {"error": "Share is not in authorized state"})
    if int(item.get("completeNonceExpiresAt", 0)) < _now_epoch():
        return _response(410, {"error": "Completion token expired"})
    if not secrets.compare_digest(nonce, str(item.get("completeNonce", ""))):
        return _response(403, {"error": "Invalid completion token"})

    _cleanup_share(item)
    return _response(200, {"status": "consumed"})


def handler(event: dict[str, Any], _context: Any) -> dict:
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    raw_path = event.get("rawPath", "/")

    if method == "OPTIONS":
        return _response(204, "")

    if raw_path == "/" and method == "GET":
        return _html_response(200, "<html><body><h1>Secure Share Proxy</h1><p>Open your full share URL.</p></body></html>")

    if raw_path.startswith("/shares/") and method == "GET":
        share_id = raw_path.removeprefix("/shares/").strip("/")
        if not share_id:
            return _response(404, {"error": "Not found"})
        item = _load_share(share_id)
        if not item:
            return _response(404, {"error": "Share not found"})
        if _is_expired(item):
            _cleanup_share(item)
            return _response(410, {"error": "Share expired"})
        if item.get("status") not in {"active", "authorized"}:
            return _response(410, {"error": "Share unavailable"})
        return _html_response(200, _share_page(share_id))

    if raw_path.startswith("/api/shares/") and raw_path.endswith("/authorize") and method == "POST":
        share_id = raw_path.removeprefix("/api/shares/").removesuffix("/authorize").strip("/")
        if not share_id:
            return _response(404, {"error": "Not found"})
        return _authorize(share_id, event)

    if raw_path.startswith("/api/shares/") and raw_path.endswith("/complete") and method == "POST":
        share_id = raw_path.removeprefix("/api/shares/").removesuffix("/complete").strip("/")
        if not share_id:
            return _response(404, {"error": "Not found"})
        return _complete(share_id, event)

    return _response(404, {"error": "Not found"})