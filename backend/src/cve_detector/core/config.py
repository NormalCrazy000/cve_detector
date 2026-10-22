"""Application settings, read from ``CVED_*`` environment variables or ``.env``."""

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class SmtpSecurity(StrEnum):
    STARTTLS = "starttls"
    SSL = "ssl"
    NONE = "none"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CVED_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Path("data")
    # Built web UI (SvelteKit static output); the API alone is served when it is missing.
    web_dir: Path = Path(__file__).resolve().parent.parent / "web"
    database_url: str | None = None
    log_level: str = "INFO"

    admin_username: str = "admin"
    # Plain text, or an argon2 hash from ``python -m cve_detector.hash_password``.
    admin_password: SecretStr | None = None
    session_days: int = 7
    # Send the session cookie over HTTPS only; enable behind a TLS reverse proxy.
    cookie_secure: bool = False

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: SmtpSecurity = SmtpSecurity.STARTTLS
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_timeout_seconds: float = 30.0
    # Optional address told when scans start failing and when they recover.
    admin_email: str | None = None

    osv_api_url: str = "https://api.osv.dev"
    http_timeout_seconds: float = 30.0
    # Parallel downloads of advisory details; keep it low to be polite to OSV.
    osv_max_workers: int = 4

    scheduler_enabled: bool = True
    # How often the scheduler looks for projects due for a scan.
    scan_tick_seconds: float = 300.0
    # After a failed scan, retry sooner than the project interval.
    scan_retry_minutes: int = 60
    # Digests mention suppressions that expire within this many days.
    suppression_expiry_warning_days: int = 7

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'cve_detector.db').resolve()}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
