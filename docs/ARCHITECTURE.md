# cve_detector — Architecture

How the tool works today and why. For what comes next see the [roadmap](ROADMAP.md); for
installation see the [README](../README.md).

## Overview

```
┌──────────────────────────── container ─────────────────────────────┐
│                                                                     │
│  SvelteKit UI (static) ──HTTP──▶ FastAPI (/api/*, admin login)      │
│                                     │                               │
│  Scheduler thread ──every few min──▶ Scan service ──▶ OSV.dev       │
│                                     │                               │
│                                     ▼                               │
│                               Diff engine ──▶ Email (SMTP)          │
│                                     │                               │
│                                     ▼                               │
│                             SQLite (/data/cve_detector.db)          │
└─────────────────────────────────────────────────────────────────────┘
```

One process in one container: FastAPI serves the API and the built web UI, and a background
thread runs the scans. It must run as a single process (no `--workers`), so that scans never
overlap.

| Area | Choice |
|------|--------|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 + Alembic (migrations run at startup), httpx2, Jinja2 |
| Frontend | SvelteKit 3 / Svelte 5 (TypeScript), `adapter-static` single-page app; API client generated from the OpenAPI schema |
| Storage | SQLite in the `/data` volume |
| Versions | [`univers`](https://github.com/aboutcode-org/univers) for Maven and npm version semantics |
| Data source | [OSV.dev](https://osv.dev), behind a `VulnSource` interface |
| Notifications | Email over SMTP, behind a `Notifier` interface |
| Distribution | Docker image built from `docker/Dockerfile`, run with `compose.yaml` |

## Code layout

```
backend/src/cve_detector/
├── main.py            # app factory, startup checks, scheduler wiring
├── web.py             # serves the built UI, security headers
├── api/               # REST routers, request/response schemas, auth dependencies
├── core/              # settings (CVED_* env vars), logging, password/session helpers
├── db/                # models, enums, session, Alembic migrations
├── ecosystems/        # Maven and npm: names, versions, ranges, manifest parsers
├── catalog.py         # shared library catalog, dependencies, manifest synchronization
├── sources/           # VulnSource interface, OSV client
├── advisories.py      # incremental advisory sync
├── cvss/              # CVSS v2, v3.x, v4.0 scoring
├── matching.py        # dependency spec × advisory ranges → affected / potentially affected
├── scanning/          # scan service, diff engine, suppressions, scheduler
├── notifiers/         # SMTP notifier, message rendering (templates/), dispatch, admin alerts
├── config_io.py       # YAML export / merge import
├── demo.py            # synthetic demo dataset
├── hash_password.py   # prints an argon2 hash for CVED_ADMIN_PASSWORD
└── export_openapi.py  # OpenAPI schema for the frontend client
frontend/src/
├── routes/            # pages: login, dashboard, projects, findings, suppressions, activity, settings
└── lib/               # API client, components, theme, formatting
```

## Data model

- **Project**: name, description, scan interval, minimum severity, included dependency scopes,
  minor-update notifications, all-clear policy, email delivery mode, last/next scan, last scan
  error, last notification.
- **Recipient**: email address of a project.
- **Library**: shared catalog, unique on `ecosystem + name` (e.g. `npm / lodash`).
- **Dependency**: project × library with a version spec (exact or range), source (manual or
  manifest type), scope (`runtime | provided | optional | development`) and directness.
- **Advisory**: OSV record with aliases, summary, severity, CVSS, affected ranges, dates, raw JSON.
- **Finding**: dependency × advisory with a status (`affected | potentially_affected | fixed |
  withdrawn`), its active suppression, first/last seen, resolution time and the state last
  notified.
- **Suppression**: advisory id or alias, optional project, reason, optional expiry.
- **ScanRun**, **NotificationLog**, **AdminSession**: history and login sessions.

## How a scan works

1. **Due projects**: the scheduler wakes every `CVED_SCAN_TICK_SECONDS` (or at once on "scan
   now") and scans all projects whose next scan is due, in a single run.
2. **One query per library**: the unique libraries of those projects are listed on OSV with one
   `querybatch` call (package only, no version). Advisory details are downloaded only when new
   or modified since the last sync.
3. **Local matching**: each dependency's spec and each advisory's affected ranges become version
   intervals. Every allowed version affected → `affected`; some → `potentially_affected`;
   ranges that cannot be evaluated → `potentially_affected` (better a finding to review than a
   silent miss).
4. **Severity**: the highest among CVSS v2 / v3.x / v4.0 scores and database labels. Advisories
   without any severity are `unknown` and always pass the project threshold.
5. **Findings are never deleted**: a finding that no longer matches becomes `fixed` (advisory
   corrected, or dependency upgraded: version changes update the dependency in place), one whose
   advisory is withdrawn becomes `withdrawn`.
6. **Failures**: a failed scan is recorded on the projects and retried after
   `CVED_SCAN_RETRY_MINUTES`; an optional admin address is told when scans start failing and when
   they recover.

## What gets notified

- Findings are always stored. The project's severity threshold, included dependency scopes and
  active suppressions only decide what is **notified**.
- Each finding remembers what its recipients were last told. Compared with the current state
  this gives **new**, **updated** (status, severity, CVSS score, fixed versions, known
  exploitation; any advisory change if the project opts in) and **resolved** findings.
- One digest per project per scan, sent only when something changed; otherwise an optional
  "no new issues" report (`never | every_run | daily | weekly`). Digests also list the findings
  still open and the suppressions expiring soon.
- The notified state is written only after a successful delivery, so restarts never re-send and
  failed sends are retried with the next digest. A suppressed finding is reported as new again
  when its suppression ends.
- Recipients get one private email each, or one shared email, per project.

## Security and privacy

- **Access**: localhost by default, LAN as an explicit opt-in; not designed for the Internet.
  Single admin from environment variables (plain password or argon2 hash); the app refuses to
  start without one or with the example value.
- **Sessions**: random tokens stored hashed server-side (logout revokes them), cookie `HttpOnly`
  and `SameSite=Strict`; state-changing calls must be same-origin JSON; failed logins throttled.
- **Browser**: Content-Security-Policy with hashes, no external resources, `X-Frame-Options`,
  `nosniff`, no referrer.
- **Container**: non-root user, read-only root filesystem, no capabilities, `no-new-privileges`.
- **Secrets** only in `.env` (never committed, never shown in the UI or logs). Recipient
  addresses are not logged at INFO level. No telemetry; emails contain no remote images, fonts
  or tracking.
- **Public repository hygiene**: author identity is the pseudonym `NormalCrazy000` with the GitHub
  noreply address; no real projects or addresses are ever committed — tests, fixtures and the
  demo use synthetic data (`example.com`, `demo-*`). gitleaks runs in pre-commit and on GitHub.

## Licensing

- The project is MIT licensed (`LICENSE`, package metadata, image label).
- Third-party code: dependencies are permissively licensed; the CVSS v4.0 calculator in `cvss/`
  is ported from the FIRST reference implementation (BSD-2-Clause).
- Data attribution: OSV.dev and the databases it aggregates (mostly CC-BY 4.0), credited in the
  README, the UI footer and every digest, with links to each advisory.
