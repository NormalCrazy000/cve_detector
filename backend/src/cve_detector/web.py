"""Serve the built web UI next to the API, plus security headers on every response."""

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, Response
from starlette.middleware.base import RequestResponseEndpoint

logger = logging.getLogger(__name__)

# SvelteKit single-page-app entry point (adapter-static ``fallback``).
FALLBACK_PAGE = "200.html"
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def mount_web_ui(app: FastAPI, web_dir: Path) -> bool:
    """Serve files from ``web_dir`` and route every other non-API path to the app."""
    root = web_dir.resolve()
    if not (root / FALLBACK_PAGE).is_file():
        logger.info("web UI not found in %s, serving the API only", root)
        return False

    @app.get("/{path:path}", include_in_schema=False)
    def web_ui(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        candidate = (root / path).resolve()
        if path and candidate.is_relative_to(root) and candidate.is_file():
            # Hashed build assets never change; everything else is revalidated.
            immutable = candidate.is_relative_to(root / "_app" / "immutable")
            cache = "public, max-age=31536000, immutable" if immutable else "no-cache"
            return FileResponse(candidate, headers={"Cache-Control": cache})
        return FileResponse(root / FALLBACK_PAGE, headers={"Cache-Control": "no-cache"})

    return True
