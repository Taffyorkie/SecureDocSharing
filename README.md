# SecureDocSharing

Minimal secure document sharing service design for one-hour AWS-backed shares.

## Security properties

- Private storage only; never expose raw S3 URLs as the primary access path.
- Share sessions expire after 1 hour.
- Recipient must match the intended email address.
- Generated passwords are displayed once and stored only as salted hashes.
- Download access also requires a one-time email verification code.
- Authorized downloads return a short-lived ZIP download reference.
- Cleanup is scheduled at share creation time for share expiry and deletion.

## Repository layout

- `app/service.py` implements share creation, password hashing, recipient validation, OTP flow, download authorization, and expiry handling.
- `app/api.py` provides simple callable entry points that can be wired to Lambda handlers or another web framework.
- `tests/test_share_service.py` covers the one-hour expiry and recipient-bound access behavior.

## Run tests

```bash
python -m pytest
```
