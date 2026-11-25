"""Application settings, loaded from environment variables (prefix MINISEAL_)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MINISEAL_", env_file=".env", extra="ignore")

    app_name: str = "MiniSeal"
    version: str = "0.1.0"


@lru_cache
def get_settings() -> Settings:
    # Cached so env is parsed once; tests can call get_settings.cache_clear().
    return Settings()
