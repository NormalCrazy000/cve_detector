# cve_detector — Roadmap

A self-hosted, Docker-first tool that tracks the libraries used by your projects,
checks them against public vulnerability databases, and notifies the right people
when something new or relevant shows up.

This document captures the decisions taken so far and the ordered steps to reach
a usable v1. Tick the boxes as work progresses.

---

## 1. Decisions

### Functional

| # | Topic | Decision |
|---|-------|----------|
| F1 | Input | Libraries are entered by the user (web UI / YAML import). Manifest import comes right after. |
| F2 | Ecosystems | **Maven** and **npm** first; the design must allow adding more (PyPI, Go, NuGet, …). |
| F3 | Versions | Both exact versions (`4.2.7`) and ranges (`^4.2.0`, `[1.0,2.0)`) are supported. |
| F4 | Projects | Defined by the user. Manifests can be imported; libraries live in a **shared, deduplicated catalog** so the same library is stored and queried once. |
| F5 | Signals | All of them, delivered in priority order: (1) new advisory affecting a tracked version, (2) severity / fix-version updates, (3) CISA KEV listing, (4) deprecated / yanked packages, (5) new upstream release. |
| F6 | Data source | **OSV.dev** first, behind a pluggable `VulnSource` interface for future sources (NVD, GitHub Advisory, …). |
| F7 | Threshold | Minimum severity configurable **per project**. |
| F8 | Schedule & email | Scan interval configurable **per project**; one **digest** email per project per run; optional configurable "all clear" report. |
| F9 | First run | Notify **everything** found (no silent baseline). |
| F10 | Recipients | Different recipients **per project**. |
| F11 | Suppressions | Yes: ignore an advisory (globally or per project) with a reason and an optional expiry date. |
| F12 | Interface | **Web app**. |
| F13 | Channels | Email first, behind a pluggable `Notifier` interface (Telegram, Slack, webhook later). |

### Technical

| Topic | Decision |
|-------|----------|
| Backend | Python 3.12+, FastAPI, SQLAlchemy 2 + Alembic, httpx2 |
| Frontend | SvelteKit (TypeScript), built with `adapter-static` and served by FastAPI → **one container** |
| Storage | SQLite on a Docker volume (`/data`) |
| Version matching | [`univers`](https://github.com/aboutcode-org/univers) (Apache-2.0) for Maven/npm version and range semantics |
| Runtime | Long-running container with an internal scheduler (one background thread that wakes every few minutes, or at once on "scan now"; runs never overlap), started with `docker compose up -d` |
| Images | Multi-arch (`linux/amd64`, `linux/arm64`), published to GHCR on tagged releases |
| CI | GitHub Actions: lint, type-check, tests, frontend build, gitleaks, dependency license check, CodeQL, Dependabot |
| Advisory fetching | OSV `querybatch` (package only) lists advisory ids + `modified` for all libraries in one call; details (`/v1/vulns/{id}`) are downloaded only when new or changed. Matching is done locally for exact versions and ranges alike. |
| Range evaluation | Interval arithmetic between the dependency spec and the advisory's affected ranges (no registry calls): all allowed versions affected → `affected`, some → `potentially_affected`. Unevaluable ranges → `potentially_affected`. |
| Severity | Highest among all CVSS vectors (v2, v3.x, v4.0) and database labels (e.g. GitHub `MODERATE`). Advisories without any severity (`unknown`) always pass the project threshold. |
| Notifications | Findings are always stored; the severity threshold, the included dependency scopes and suppressions only decide what is notified. Re-notified only on significant changes (status, severity, CVSS score, fixed versions, known exploitation), or on any advisory change if the project opts in. Resolved findings (no longer matching or withdrawn) are reported once and kept as history. |
| CVSS | Own implementation of v2 and v3.x; v4.0 ported from the FIRST reference calculator (BSD-2-Clause), verified against it on 20,000 random vectors. |
| License | **MIT** |
| Language | Everything in the repo in **English** |

### Privacy, deployment & access

| Topic | Decision |
|-------|----------|
| Identity | Pseudonym only: author `NormalCrazy000` with the GitHub **noreply** email; `LICENSE` copyright `NormalCrazy000`. No real name, no personal email anywhere. |
| Platforms | Multi-arch image: `linux/amd64` + `linux/arm64` (x86 servers, Raspberry Pi, Apple Silicon). |
| Distribution | GHCR, published by GitHub Actions on every `vX.Y.Z` tag; local `docker compose build` still supported. |
| Web access | Localhost / LAN only, single admin login (credentials from environment). Port bound to `127.0.0.1` by default; LAN exposure is an explicit opt-in. Not designed to be exposed to the Internet. |
| SMTP | Generic (host/port/STARTTLS or SSL/user/password); docs show Gmail App Password as an example. |
| User data | Real projects/libraries/recipients are **never** committed — only an anonymized example config. |

---

## 2. Architecture

```
┌──────────────────────────── container ────────────────────────────┐
│                                                                    │
│  SvelteKit static UI  ──HTTP──▶  FastAPI (REST /api/*)             │
│                                     │                              │
│                                     ▼                              │
│   Scheduler (thread)      ──▶  Scan service ──▶ VulnSource(s)      │
│        tick every N min            │              └ OSV.dev        │
│                                     │            Enrichers         │
│                                     │              ├ CISA KEV      │
│                                     │              ├ EPSS (later)  │
│                                     │              └ Registry info │
│                                     ▼                (npm/Maven)   │
│                               Diff engine ──▶ Notifier(s)          │
│                                     │            └ Email (SMTP)    │
│                                     ▼                              │
│                               SQLite (/data/cve_detector.db)       │
└────────────────────────────────────────────────────────────────────┘
```

### Data model (first draft)

- **Project**: name, description, scan interval, min severity, included dependency scopes, minor-update notifications on/off, all-clear policy (`never|every_run|daily|weekly`), last/next scan, last scan error.
- **Recipient**: project → email address (and later: channel type + target).
- **Library** (shared catalog, unique on `ecosystem + name`): e.g. `Maven / org.apache.logging.log4j:log4j-core`, `npm / lodash`.
- **Dependency**: project → library + `version_spec` + `is_exact` + source (`manual|pom.xml|package.json|package-lock.json|mvn-dependency-list`)
  + scope (`runtime|provided|optional|development`, normalized across ecosystems) + `is_direct` (unknown for `mvn dependency:list`).
- **Advisory**: OSV id, aliases (CVE ids, GHSA ids), summary, severity / CVSS vector + score, affected ranges, fixed versions, `published`, `modified`, `withdrawn`, raw JSON.
- **Finding**: dependency × advisory, status (`affected|potentially_affected|fixed|withdrawn`), active suppression, first seen, last seen, resolved at, last notified state.
- **Suppression**: advisory id, optional project scope, reason, created by, expires at.
- **ScanRun**: start/end, status, counters, errors.
- **NotificationLog**: project, channel, sent at, content hash, result.

### Key behaviours

1. **Deduplication**: a scan collects the *unique* libraries of all due projects and queries each library once, then fans out results to projects.
2. **Exact vs range**:
   - exact version → OSV `querybatch` with the version → `affected` / not affected.
   - range → fetch all advisories for the package, evaluate the range locally with `univers`:
     every allowed version affected → `affected`; some → `potentially_affected` (shown separately in the digest).
3. **Change detection**: compare stored `modified`, severity, fixed versions and KEV flag; changes generate a "updated advisory" entry.
4. **Digest**: one email per project per run, grouped by severity, with: new findings, updated findings, KEV hits, deprecations, new releases (if enabled), expiring suppressions. "All clear" email only if the project's policy says so.
5. **Idempotency**: each finding stores the state last notified, written only after a successful send; a finding is re-notified only when that state changes, so restarts never spam and failed sends are retried.
6. **Resilience**: HTTP retries with backoff, OSV rate limiting, a failed scan is reported in the UI (and optionally by email to an admin address).

---

## 3. Privacy & public-repo hygiene

Do these **before the first commit**.

- [x] Set the commit identity for this repo to the GitHub noreply address:
  ```bash
  # numeric ID: https://api.github.com/users/NormalCrazy000  → "id"
  git config user.name  "NormalCrazy000"
  git config user.email "<ID>+NormalCrazy000@users.noreply.github.com"
  ```
- [x] GitHub → Settings → Emails: enable **Keep my email addresses private** and **Block command line pushes that expose my email**.
- [x] Verify before every push: `git log --format='%an <%ae>' | sort -u`.
- [x] `.gitignore` covers: `.env`, `*.db`, `data/`, `config.yaml` (real config), `node_modules/`, `.venv/`, build output, IDE folders.
- [x] Ship only `config.example.yaml` and `.env.example` with fake data (`example.com`, `demo-project`).
- [x] Add a **gitleaks** pre-commit hook and CI job (secrets scanning).
- [x] Enable GitHub **secret scanning** and **push protection** on the repository.
- [ ] Tests and fixtures use synthetic data only; screenshots in the README use the demo dataset.
- [ ] Secrets (SMTP password, admin password, session key) only via env vars or Docker secrets, never in YAML in the repo, never logged (mask them in logs and in the UI).
- [ ] No telemetry, no external assets in emails (no tracking pixels, no remote fonts/images).
- [ ] Logs must not contain recipient addresses at INFO level.
- [x] `SECURITY.md` with a private reporting channel (GitHub "Private vulnerability reporting", not a personal email).

---

## 4. Licensing checklist

- [x] `LICENSE` — MIT, `Copyright (c) 2026 NormalCrazy000`.
- [ ] SPDX headers optional; `pyproject.toml` → `license = "MIT"`, `package.json` → `"license": "MIT"`.
- [ ] OCI image label `org.opencontainers.image.licenses="MIT"`.
- [ ] Dependency license policy: allow MIT, BSD, Apache-2.0, ISC, MPL-2.0, PSF; fail CI on GPL/AGPL/unknown in shipped dependencies.
  - Python: `pip-licenses --fail-on ...`
  - npm: `license-checker --onlyAllow ...`
- [ ] `THIRD_PARTY_NOTICES.md` generated from the above (required by Apache-2.0 deps such as `univers`), plus the BSD-2-Clause notice of the FIRST CVSS v4 calculator ported in `cvss/`.
- [ ] Data attribution in README and in the UI footer:
  - **OSV.dev** — data aggregated from several sources; most are CC-BY 4.0 (e.g. GitHub Advisory Database). Credit OSV and link to the advisory source.
  - **CISA KEV** — public US government data; cite the source.
  - **EPSS** (when added) — cite FIRST.org as requested by their usage terms.
  - **NVD** (if ever added) — mandatory notice: *"This product uses the NVD API but is not endorsed or certified by the NVD."*
- [ ] README disclaimer: provided "as is", no guarantee of completeness; absence of findings ≠ absence of vulnerabilities.
- [x] No external contributions accepted for now (no `CONTRIBUTING.md`); if this changes, add one stating contributions are accepted under MIT (inbound = outbound).

---

## 5. Repository layout

```
cve_detector/
├── backend/
│   ├── pyproject.toml
│   ├── alembic/
│   ├── src/cve_detector/
│   │   ├── api/            # FastAPI routers
│   │   ├── core/           # settings, security, logging
│   │   ├── db/             # models, session
│   │   ├── ecosystems/     # maven.py, npm.py  (version + manifest parsing)
│   │   ├── sources/        # base.py (VulnSource), osv.py
│   │   ├── enrichers/      # kev.py, epss.py, registry.py
│   │   ├── notifiers/      # base.py (Notifier), email.py, templates/
│   │   ├── scanning/       # scheduler.py, scan.py, diff.py
│   │   └── main.py
│   └── tests/
├── frontend/               # SvelteKit app (adapter-static)
├── docker/
│   └── Dockerfile
├── docs/
│   └── ROADMAP.md
├── .github/
│   ├── workflows/          # ci.yml, release.yml, codeql.yml
│   └── dependabot.yml
├── compose.yaml
├── config.example.yaml
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── LICENSE
├── README.md
├── SECURITY.md
└── THIRD_PARTY_NOTICES.md
```

---

## 6. Step-by-step plan

### Phase 0 — Repository bootstrap
- [x] Fix git identity (section 3) and verify.
- [x] Add `LICENSE`, `.gitignore`, `README.md` skeleton, `SECURITY.md`.
- [x] Add `.pre-commit-config.yaml`: gitleaks, ruff, ruff-format, prettier, end-of-file fixer.
- [x] First commit and push; enable secret scanning, push protection, Dependabot, private vulnerability reporting on GitHub.

### Phase 1 — Backend skeleton
- [x] `backend/` with `uv` (or Poetry), FastAPI app, `/api/health`.
- [x] Settings via `pydantic-settings` (env vars, `.env` for local dev).
- [x] SQLAlchemy models from section 2 + first Alembic migration.
- [x] Tooling: ruff, mypy (strict), pytest, coverage.

### Phase 2 — Ecosystems & catalog
- [x] `Ecosystem` interface: `normalize_name`, `parse_version`, `parse_spec`, `parse_range`, manifest parsers.
- [x] Maven: `groupId:artifactId`, Maven version ranges (`[1.0,2.0)`), `pom.xml` parsing (direct deps, `${property}` resolution, `dependencyManagement`). Documented limit: no parent POM / BOM / transitive resolution — such versions are reported as unresolved and must be completed by the user; for full coverage import `mvn dependency:list` output (later: CycloneDX SBOM).
- [x] Maven: `mvn dependency:list` output import (exact versions, transitives included).
- [x] npm: semver ranges (`^`, `~`, `x`, `||`, hyphen), `package.json` (direct deps, `npm:` aliases; git/file/URL deps skipped with a warning; dist-tags reported as unresolved) and `package-lock.json` v2/v3 (exact, includes transitives, flagged as direct or not).
- [x] Dependency scope (runtime / provided / optional / development) imported for every source; dev/test dependencies are kept, filtering is a per-project choice.
- [x] Catalog upsert so each `ecosystem + name` exists once; dependencies reference it.
- [x] Unit tests with synthetic manifests.

### Phase 3 — Vulnerability source (OSV)
- [x] `VulnSource` interface: `list_advisories(packages) -> ids + modified`, `fetch_advisories(ids) -> advisories`.
- [x] OSV client: `POST /v1/querybatch` (package-only queries, batches of 500, per-query pagination), `GET /v1/vulns/{id}` in parallel (configurable workers); retries with backoff on network errors, 429 (honouring `Retry-After`) and 5xx; timeouts.
- [x] Advisory sync: only new or modified advisories are downloaded and upserted.
- [x] Severity normalization: CVSS v2/v3.x/v4.0 vectors → score + label, plus database labels; the highest wins.
- [x] Local range evaluation with version intervals → `affected` / `potentially_affected`. Verified against OSV server-side matching on real packages (npm and Maven).
- [x] Tests with synthetic OSV responses (no network in CI); CVSS v4 tests use reference scores from the FIRST calculator.

### Phase 4 — Scan engine & diff
- [x] Scan service: collect due projects → unique libraries → query → upsert advisories → compute findings. A failed scan is retried after `CVED_SCAN_RETRY_MINUTES` (default 60) instead of the full interval.
- [x] Diff engine: new / updated / resolved findings against the last notified state; minor advisory changes notified only if the project opts in.
- [x] Apply per-project severity threshold (`unknown` severity always passes) and active suppressions (by advisory id or alias); flag suppressions expiring within `CVED_SUPPRESSION_EXPIRY_WARNING_DAYS` (default 7). A suppressed finding is reported as new again when its suppression ends.
- [x] Withdrawn advisories close their findings.
- [x] Per-project dependency scope filter (choose the included scopes; default: all).
- [x] Scheduler: tick every `CVED_SCAN_TICK_SECONDS` (default 300), run projects whose `next_scan_at` is due in one run; a single thread so runs never overlap; runs interrupted by a restart are marked failed.
- [x] Manual "scan now" endpoint (`POST /api/projects/{id}/scan`): queued if a scan is running, never lost.

### Phase 5 — Notifications
- [ ] `Notifier` interface: `send(project, digest) -> result`; registry of channels.
- [ ] Email notifier: SMTP with STARTTLS/SSL, HTML + plain-text multipart, Jinja2 templates, no external resources.
- [ ] Digest builder grouped by severity, with links to OSV/CVE pages and fixed versions.
- [ ] "All clear" policy per project.
- [ ] NotificationLog + "send test email" endpoint.
- [ ] Tests with a fake SMTP server (e.g. `aiosmtpd`).

### Phase 6 — REST API & auth
- [ ] CRUD: projects, recipients, dependencies, suppressions.
- [ ] Manifest upload endpoint (`pom.xml`, `package.json`, `package-lock.json`) with preview before saving.
- [ ] YAML import/export of the whole configuration.
- [ ] Read endpoints: findings (filters by project / severity / status), scan runs, notification log.
- [ ] Auth: single admin from env, password hashed (argon2), HTTP-only `SameSite=Strict` session cookie, login rate limiting.
- [ ] OpenAPI schema → generate the TypeScript client for the frontend.

### Phase 7 — Web app (SvelteKit)
- [ ] SvelteKit + TypeScript + `adapter-static`; a light component library or plain CSS.
- [ ] Pages: login, dashboard (counts by severity, last scans), projects list/detail, dependency editor + manifest import, findings table, suppressions, settings (SMTP test, notifications).
- [ ] Build output copied into the backend image and served by FastAPI.
- [ ] Basic E2E test (Playwright) on the demo dataset.

### Phase 8 — Docker
- [ ] Multi-stage `Dockerfile`: Node stage builds the UI → Python slim runtime; non-root user; `HEALTHCHECK`; `/data` volume.
- [ ] `compose.yaml` with env file, volume, port bound to `127.0.0.1:8080`, restart policy.
- [ ] README "Quick start": `cp .env.example .env` → edit → `docker compose up -d`.
- [ ] Document LAN opt-in (`0.0.0.0` binding) and state clearly that Internet exposure is unsupported.

### Phase 9 — CI/CD & release
- [ ] `ci.yml`: ruff, mypy, pytest, frontend lint/check/build, gitleaks, license checks.
- [ ] `codeql.yml` for Python and JavaScript; `dependabot.yml` for pip, npm, GitHub Actions, Docker.
- [ ] `release.yml`: on tag `v*`, build multi-arch image with Buildx, push to `ghcr.io/normalcrazy000/cve_detector`, generate image SBOM, optional cosign signature.
- [ ] Dogfooding: the tool scans its own dependencies in a demo project.
- [ ] Tag **v0.1.0**.

### Phase 10 — Enrichment (security signals first)
- [ ] CISA KEV feed (daily download) → "actively exploited" flag, always notified regardless of threshold (configurable).
- [ ] EPSS score to help prioritize.
- [ ] npm registry: `deprecated` field, new `latest` version.
- [ ] Maven Central: new versions via `maven-metadata.xml`; relocations.
- [ ] Toggle per project for "new release" notifications (noisy by nature).

### Phase 11 — Later
- [ ] More ecosystems: PyPI, Go, NuGet, Cargo, Composer.
- [ ] CycloneDX / SPDX SBOM import.
- [ ] More notifiers: Telegram, Slack, Discord, generic webhook.
- [ ] More sources: GitHub Advisory API, NVD.
- [ ] Remote manifest fetch from Git repositories (with token).
- [ ] Multi-user with roles.

---

## 7. Definition of done for v1

- A user can run `docker compose up -d`, log into the web app, create a project with Maven and npm dependencies (manual or from manifests), set interval, threshold and recipients.
- Scans run on schedule, find OSV advisories for exact and ranged versions, and send a digest email per project, plus an optional all-clear report.
- Suppressions work and expire.
- The public repo contains no personal data, passes gitleaks and license checks, and ships with MIT license and data-source attribution.
