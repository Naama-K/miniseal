# MiniSeal API + UI. Build: docker compose build   Run: docker compose up
FROM python:3.14-slim

# No .pyc files (the root filesystem is read-only at runtime), logs straight
# to stdout, no pip cache in the image.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# An unprivileged user. /data is created here, owned by that user, so a
# fresh named volume mounted on it inherits the ownership.
RUN useradd --create-home --uid 10001 miniseal \
 && mkdir /data && chown miniseal:miniseal /data

# Dependencies first, code second: editing the code doesn't re-run pip
# (Docker reuses the cached dependency layer).
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY docker-entrypoint.sh ./

USER miniseal
ENV MINISEAL_DB_PATH=/data/miniseal.db
EXPOSE 8000

# Healthy = READY (key loaded, database reachable), not merely "process up".
# Plain Python: the slim image has no curl.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2).status == 200 else 1)"]

# `sh script` rather than executing it: works even if the exec bit is lost
# (e.g. checked out on Windows).
ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
# One worker: SQLite has a single writer anyway, and the per-process caches
# (signer, stores) stay simple. Scale out = Postgres + more containers.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
