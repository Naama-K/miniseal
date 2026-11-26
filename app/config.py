"""Application settings, loaded from environment variables (prefix MINISEAL_)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MINISEAL_", env_file=".env", extra="ignore")

    app_name: str = "MiniSeal"
    version: str = "0.1.0"

    # Base64 Ed25519 seed. SecretStr keeps it out of logs and repr().
    signing_key: SecretStr | None = None
    # Or a file holding the same key (set one, not both). The app only reads
    # it: a typo in the path must fail, not mint a new key that orphans seals.
    signing_key_file: str | None = None

    # The pixel cap stops "decompression bombs": tiny files that decode to
    # gigabytes of pixels.
    max_upload_bytes: int = 10 * 1024 * 1024
    max_image_pixels: int = 40_000_000

    db_path: str = "miniseal.db"

    # Scores at or above this are "suspicious". Lower it to catch more fakes
    # at the cost of more false alarms.
    detector_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # "always": seal every image and record the detector's verdict. A seal
    #   certifies origin, not truth.
    # "reject_suspicious": refuse (422) images the detector flags, for
    #   publishers who never want their name on a likely fake.
    seal_policy: Literal["always", "reject_suspicious"] = "always"

    # Self-service sign-up (POST /signup). No email check or rate limit
    # behind it, so it's off by default; keys come from the admin CLI.
    open_signup: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
