# syntax=docker/dockerfile:1
# Build from the repository root: docker build -f docker/Dockerfile .

# --- Web UI: static SvelteKit build -------------------------------------------------
FROM node:24-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Python dependencies and the app, installed into a virtualenv -------------------
FROM python:3.12-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.9.3 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src/backend
# Dependencies first, so that code changes do not invalidate this layer.
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY backend/src ./src
COPY --from=web /src/frontend/build ./src/cve_detector/web
RUN uv sync --locked --no-dev --no-editable

# --- Runtime ------------------------------------------------------------------------
FROM python:3.12-slim-bookworm
ARG VERSION=dev
LABEL org.opencontainers.image.title="cve_detector" \
      org.opencontainers.image.description="Self-hosted vulnerability tracker for project dependencies" \
      org.opencontainers.image.source="https://github.com/NormalCrazy000/cve_detector" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown app:app /data
COPY --from=build /app/.venv /app/.venv

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CVED_DATA_DIR=/data

USER app
WORKDIR /data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4)"]
# One process only: the scan scheduler runs inside it (never use --workers).
# No access log: the healthcheck would add a line every 30 s; the app logs scan summaries.
CMD ["uvicorn", "cve_detector.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--no-access-log"]
