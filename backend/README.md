# cve_detector — backend

FastAPI service, scheduler and scan engine. See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

```bash
uv sync                                    # install dependencies
CVED_ADMIN_PASSWORD=dev uv run uvicorn cve_detector.main:app --reload
uv run pytest                              # tests (no network)
uv run ruff check . && uv run mypy         # lint & type-check
```

Configuration is read from `CVED_*` environment variables or a `.env` file
(see `../.env.example`). Database migrations run automatically at startup.

Useful commands:

```bash
uv run python -m cve_detector.demo            # synthetic demo data in an empty database
uv run python -m cve_detector.hash_password   # argon2 hash for CVED_ADMIN_PASSWORD
uv run alembic revision --autogenerate -m "describe the change"   # after changing models
uv run python -m cve_detector.export_openapi > ../frontend/openapi.json   # after changing the API
```
