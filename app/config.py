from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    share_ttl_seconds: int = int(os.getenv("SHARE_TTL_SECONDS", "3600"))
    otp_ttl_seconds: int = int(os.getenv("OTP_TTL_SECONDS", "600"))
    download_url_ttl_seconds: int = int(os.getenv("DOWNLOAD_URL_TTL_SECONDS", "300"))
    s3_bucket_name: str = os.getenv("S3_BUCKET_NAME", "secure-doc-sharing")
    kms_key_id: str = os.getenv("KMS_KEY_ID", "alias/secure-doc-sharing")


settings = Settings()
