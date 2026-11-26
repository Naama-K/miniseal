"""Application settings, loaded from environment variables (prefix MINISEAL_)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MINISEAL_", env_file=".env", extra="ignore")

    app_name: str = "MiniSeal"
    version: str = "0.1.0"

    # Base64 Ed25519 seed. SecretStr keeps it out of logs and repr():
    # printing settings shows '**********' instead of the key.
    signing_key: SecretStr | None = None
    # Or: a file holding that same base64 key (the Docker convention for
    # secrets: *_FILE). Set one of the two, not both. The app only READS this
    # file; creating it is an explicit step (`python -m app.crypto ensure`,
    # run by the container on start), so a typo in the path fails loudly
    # instead of quietly minting a new key that orphans every existing seal.
    signing_key_file: str | None = None

    # Upload limits. The byte cap stops huge uploads; the pixel cap stops
    # "decompression bombs" (a tiny file that decodes to gigabytes of pixels).
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_image_pixels: int = 40_000_000  # ~40 megapixels

    # SQLite file for the seal registry. Relative paths resolve against the
    # working directory; in Docker this points into a mounted volume.
    db_path: str = "miniseal.db"

    # Detector scores at or above this are labelled "suspicious". Policy, not
    # model: lower it to catch more fakes at the price of more false alarms.
    detector_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # What /seal does with an image the detector calls suspicious.
    # "always": seal it anyway and record the verdict (default). A seal
    #   certifies origin, not truth, and a detector is only a guess.
    # "reject_suspicious": refuse with 422; for customers who only want
    #   to put their name on images that passed the check.
    seal_policy: Literal["always", "reject_suspicious"] = "always"

    # Self-service sign-up (POST /signup): anyone can get an API key by
    # choosing a free name. Off by default: there is no email check, CAPTCHA
    # or rate limit behind it, so it's for demos, not for production, where
    # keys come from a real account system (or the admin CLI, app.auth).
    open_signup: bool = False


@lru_cache
def get_settings() -> Settings:
    # Cached so env is parsed once; tests can call get_settings.cache_clear().
    return Settings()
