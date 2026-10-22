# cve_detector web UI

SvelteKit (Svelte 5, TypeScript) single-page app, built to static files and served by the
backend: one container, one port.

## Development

```bash
# terminal 1 — backend on :8000 (see ../backend/README.md)
cd ../backend && CVED_ADMIN_PASSWORD=dev uv run uvicorn cve_detector.main:app --reload

# terminal 2 — UI on :5173, /api is proxied to the backend
npm install
npm run dev
```

Optional demo data for an empty database: `cd ../backend && uv run python -m cve_detector.demo`.

## Checks

```bash
npm run check      # svelte-check (types, a11y)
npm run build      # static output in build/
npm run test:e2e   # Playwright: builds, starts the backend on a fresh demo database, runs e2e/
```

Locally the end-to-end tests use the installed Google Chrome; in CI Playwright's Chromium is used.
`SCREENSHOTS=<dir> npm run test:e2e` also saves light/dark screenshots of the demo dataset.

## API client

`src/lib/api/schema.d.ts` is generated from the backend's OpenAPI schema; regenerate both after
changing the API (a backend test fails when `openapi.json` is out of date):

```bash
cd ../backend && uv run python -m cve_detector.export_openapi > ../frontend/openapi.json
cd ../frontend && npm run gen:api
```
