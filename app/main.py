"""FastAPI entrypoint."""
from fastapi import FastAPI

from app.config import get_settings


def create_app() -> FastAPI:
    # App factory: lets tests build a fresh app with different settings.
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.version)

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        return {"status": "ok", "version": settings.version}

    return app


app = create_app()
