# cve_detector

> **Status: early development — not usable yet.** See the [roadmap](docs/ROADMAP.md).

A self-hosted, Docker-first tool that tracks the libraries used by your projects,
checks them against public vulnerability databases and emails a digest to each
project's recipients when something new or relevant shows up.

## Planned features

- Projects with their own libraries, scan interval, severity threshold and recipients
- Maven and npm first (exact versions and ranges), more ecosystems later
- Import from `pom.xml`, `package.json`, `package-lock.json`
- Vulnerability data from [OSV.dev](https://osv.dev), pluggable sources
- Digest emails, optional "all clear" reports, pluggable notification channels
- Suppressions with reason and expiry date
- Web UI, single container, `docker compose up -d`

## Development

```bash
pip install pre-commit   # or: uv tool install pre-commit
pre-commit install
```

Never commit real configuration: use `.env.example` as a template for your local `.env`.

## Data sources & attribution

Vulnerability data is provided by [OSV.dev](https://osv.dev), which aggregates
advisories from several databases (e.g. the GitHub Advisory Database, CC-BY 4.0).
Each advisory links back to its original source.

## Disclaimer

This software is provided "as is", without warranty of any kind. The absence of
findings does not mean the absence of vulnerabilities.

## License

[MIT](LICENSE)
