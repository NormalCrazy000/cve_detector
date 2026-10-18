"""Alembic environment.

The database URL comes from the ``sqlalchemy.url`` option when set programmatically
(see ``cve_detector.db.migrate``), otherwise from the application settings.
"""

from logging.config import fileConfig

from alembic import context

from cve_detector.core.config import get_settings
from cve_detector.db import models  # noqa: F401  (registers the models)
from cve_detector.db.base import Base
from cve_detector.db.session import make_engine

config = context.config

# Only configure logging when run from the CLI, not when called by the app.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().sqlalchemy_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite cannot ALTER most constraints in place
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
