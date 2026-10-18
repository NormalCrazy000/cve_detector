from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from cve_detector.db.base import Base
from cve_detector.db.session import make_engine


def test_migrations_match_models(db_url: str) -> None:
    """Fails when models change without a matching Alembic migration."""
    engine = make_engine(db_url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        diff = compare_metadata(context, Base.metadata)
    engine.dispose()

    assert diff == []
