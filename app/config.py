"""Application settings, loaded from environment variables (prefix MINISEAL_)."""
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MINISEAL_", env_file=".env", extra="ignore")

    app_name: str = "MiniSeal"
    version: str = "0.1.0"

    # Base64 Ed25519 seed. SecretStr keeps it out of logs and repr():
    # printing settings shows '**********' instead of the key.
    signing_key: SecretStr | None = None

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


@lru_cache
def get_settings() -> Settings:
    # Cached so env is parsed once; tests can call get_settings.cache_clear().
    return Settings()
