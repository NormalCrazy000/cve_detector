# cve_detector — Roadmap

What is done, what comes next. How things work is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Done

| Phase | Content |
|-------|---------|
| 0 — Bootstrap | License, pseudonymous identity, pre-commit (gitleaks, ruff), GitHub secret scanning |
| 1 — Backend skeleton | FastAPI, settings, SQLAlchemy models, Alembic, strict tooling |
| 2 — Ecosystems & catalog | Maven and npm versions/ranges; `pom.xml`, `mvn dependency:list`, `package.json`, `package-lock.json`; shared library catalog |
| 3 — OSV source | Incremental advisory sync, CVSS v2/v3/v4, local range matching |
| 4 — Scan engine | Scheduler, diff engine, thresholds, scopes, suppressions, "scan now" |
| 5 — Notifications | SMTP digests, all-clear reports, notification log, admin alerts |
| 6 — REST API & auth | CRUD, manifest preview and sync, YAML backup, findings/history endpoints, admin login |
| 7 — Web UI | SvelteKit app, light/dark theme, demo dataset, Playwright end-to-end tests |
| 8 — Docker | Hardened image, `compose.yaml`, quick start, backup/restore |

## Phase 9 — CI/CD & release (planned, not started)

- [ ] `ci.yml` on every push and pull request: ruff, mypy, pytest, svelte-check, frontend build,
  Playwright end-to-end tests, Docker build, dependency license check (allow MIT, BSD,
  Apache-2.0, ISC, MPL-2.0, PSF in shipped dependencies).
- [ ] `release.yml` on `vX.Y.Z` tags: build the image for `linux/amd64` and `linux/arm64` and attach
  both as `docker save` archives (`.tar.gz`) to the GitHub Release, with release notes. No
  container registry for now. Users run `docker load -i <file>` then `docker compose up -d`.
- [ ] `codeql.yml` for Python and JavaScript.
- [ ] `dependabot.yml` extended to uv/pip, npm and the Dockerfile base images (GitHub Actions are
  already covered).
- [ ] Third-party actions pinned to commit hashes; minimal permissions per workflow.
- [ ] `THIRD_PARTY_NOTICES.md` generated from the license check, including the BSD-2-Clause notice
  of the FIRST CVSS v4 calculator.
- [ ] README screenshots from the demo dataset (`SCREENSHOTS=<dir> npm run test:e2e`).
- [ ] Tag **v0.1.0**.

## TODO (decided to postpone)

- [ ] Sign release images and attach an SBOM (cosign keyless): only useful once the project has
  external users.
- [ ] Dogfooding: a `python -m cve_detector.check <manifest>` command and a weekly workflow
  scanning `frontend/package-lock.json` (Dependabot alerts cover this meanwhile).
- [ ] Prettier for the frontend, checked in CI and pre-commit.
- [ ] Login throttling inside Docker: every request comes from the Docker gateway address, so
  five wrong passwords block everyone for a while; consider a per-username or global backoff.
- [ ] Optionally publish the image to a container registry (GHCR) for `docker compose pull`.

## Phase 10 — Enrichment

- [ ] CISA KEV feed (daily download) → "actively exploited" flag, always notified regardless of
  the threshold (configurable). Credit CISA as the source.
- [ ] EPSS score to help prioritize (credit FIRST.org as their terms require).
- [ ] npm registry: `deprecated` field, new `latest` version.
- [ ] Maven Central: new versions via `maven-metadata.xml`; relocations.
- [ ] Per-project toggle for "new release" notifications (noisy by nature).

## Phase 11 — Later

- [ ] More ecosystems: PyPI, Go, NuGet, Cargo, Composer.
- [ ] CycloneDX / SPDX SBOM import.
- [ ] More notifiers: Telegram, Slack, Discord, generic webhook.
- [ ] More sources: GitHub Advisory API, NVD (with its mandatory notice: "This product uses the
  NVD API but is not endorsed or certified by the NVD.").
- [ ] Remote manifest fetch from Git repositories (with token).
- [ ] Multi-user with roles.

## Definition of done for v1

- `docker compose up -d`, log in, create projects with Maven and npm dependencies (manual or
  from manifests), set interval, threshold and recipients. ✅
- Scheduled scans find OSV advisories for exact and ranged versions and send a digest per
  project, plus optional all-clear reports. ✅
- Suppressions work and expire. ✅
- The public repository contains no personal data, passes gitleaks and license checks, and ships
  with the MIT license and data-source attribution. — license check pending (Phase 9).
