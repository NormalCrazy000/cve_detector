# cve_detector — backend

FastAPI service, scheduler and scan engine. See the [roadmap](../docs/ROADMAP.md).

```bash
uv sync                                    # install dependencies
uv run uvicorn cve_detector.main:app --reload
uv run pytest                              # tests
uv run ruff check . && uv run mypy         # lint & type-check
```

Configuration is read from `CVED_*` environment variables or a `.env` file
(see `../.env.example`). Database migrations run automatically at startup.

Create a new migration after changing the models:

```bash
uv run alembic revision --autogenerate -m "describe the change"
```
