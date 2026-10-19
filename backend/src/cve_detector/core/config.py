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
    database_url: str | None = None
    log_level: str = "INFO"

    admin_username: str = "admin"
    admin_password: SecretStr | None = None
    secret_key: SecretStr | None = None

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: SmtpSecurity = SmtpSecurity.STARTTLS
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None

    osv_api_url: str = "https://api.osv.dev"
    http_timeout_seconds: float = 30.0
    # Parallel downloads of advisory details; keep it low to be polite to OSV.
    osv_max_workers: int = 4

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'cve_detector.db').resolve()}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
