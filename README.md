# cve_detector

> **Status: pre-release.** Usable with Docker built from source; no published image or
> tagged release yet. See the [roadmap](docs/ROADMAP.md).

A self-hosted, Docker-first tool that tracks the libraries used by your projects,
checks them against public vulnerability databases and emails a digest to each
project's recipients when something new or relevant shows up.

## Features

- Projects with their own dependencies, scan interval, severity threshold, dependency types and recipients
- Maven and npm, exact versions and ranges (`^4.2.0`, `[1.0,2.0)`); more ecosystems later
- Import from `pom.xml`, `package.json`, `package-lock.json` and `mvn dependency:list`, with a preview
- Vulnerability data from [OSV.dev](https://osv.dev), CVSS v2/v3/v4 scoring
- One digest email per project: new, updated and resolved findings; optional "no new issues" reports
- Suppressions with reason and expiry date
- Web UI with a single admin login, light/dark theme; YAML export/import of the configuration
- Single container, `docker compose up -d`, data in a Docker volume

## Quick start

Requirements: Docker with the Compose plugin.

```bash
git clone https://github.com/NormalCrazy000/cve_detector.git
cd cve_detector
cp .env.example .env
# edit .env: at least CVED_ADMIN_PASSWORD, and the CVED_SMTP_* settings to receive emails
docker compose up -d --build
```

Open <http://127.0.0.1:8080>, log in with `CVED_ADMIN_USERNAME` / `CVED_ADMIN_PASSWORD`, create a
project, add or import its dependencies and its recipients. The first scan runs within a few
minutes; use **Settings → Send test email** to check the email configuration.

The container refuses to start without an admin password, or with the example one.
`docker compose logs -f` shows what it is doing.

### Configuration

All settings are environment variables in `.env`, documented in [`.env.example`](.env.example):
admin account, SMTP server, optional admin address for failing scans, scheduler timings.
To avoid keeping the admin password in clear text, store its argon2 hash instead:

```bash
docker compose run --rm --no-deps cve-detector python -m cve_detector.hash_password
```

### Access from the local network

By default the UI listens on `127.0.0.1` only. To reach it from other devices of your LAN, set
`CVED_BIND_ADDRESS=0.0.0.0` (and optionally `CVED_PORT`) in `.env`, then `docker compose up -d`.
cve_detector is **not designed to be exposed to the Internet**: keep it behind your firewall, or
behind a VPN. Behind a TLS reverse proxy also set `CVED_COOKIE_SECURE=true`.

### Backup and restore

Data (projects, findings, history) lives in the Docker volume `cve-detector-data`. The
configuration alone can also be exported as YAML from **Settings**.

```bash
# backup: stop for a consistent copy, archive the volume into the current directory
docker compose stop
docker run --rm -v cve-detector-data:/data:ro -v "$PWD":/backup busybox:1.37 \
  tar czf /backup/cve-detector-backup.tgz -C /data .
docker compose start

# restore (replaces the current data)
docker compose down
docker volume rm cve-detector-data
docker run --rm -v cve-detector-data:/data -v "$PWD":/backup:ro busybox:1.37 \
  sh -c 'tar xzf /backup/cve-detector-backup.tgz -C /data && chown -R 10001:10001 /data'
docker compose up -d
```

### Update

```bash
git pull
docker compose up -d --build
```

Database migrations run automatically at startup.

### Try it with demo data

On an **empty** installation, this fills the database with made-up projects and advisories
(`demo-*`, `DEMO-2026-*`) to explore the UI; delete those projects afterwards:

```bash
docker compose run --rm cve-detector python -m cve_detector.demo
```

### Uninstall

`docker compose down` stops and removes the container; add `-v` to delete the data volume too.

## Development

```bash
pip install pre-commit   # or: uv tool install pre-commit
pre-commit install
```

Backend: see [backend/README.md](backend/README.md). Web UI: see [frontend/README.md](frontend/README.md).

Never commit real configuration: use `.env.example` as a template for your local `.env`.

## Contributions

This is a personal project and external contributions (pull requests) are not
accepted at the moment. Bug reports are welcome as issues; security problems go
through [SECURITY.md](SECURITY.md).

## Data sources & attribution

Vulnerability data is provided by [OSV.dev](https://osv.dev), which aggregates
advisories from several databases (e.g. the GitHub Advisory Database, CC-BY 4.0).
Each advisory links back to its original source.

## Disclaimer

This software is provided "as is", without warranty of any kind. The absence of
findings does not mean the absence of vulnerabilities.

## License

[MIT](LICENSE)
