from saastesa.api.db import _normalize_database_url


def test_normalize_postgres_scheme_alias() -> None:
    raw = "postgres://user:pass@host:5432/db"
    assert _normalize_database_url(raw).startswith("postgresql+psycopg://")


def test_normalize_postgresql_scheme() -> None:
    raw = "postgresql://user:pass@host:5432/db"
    assert _normalize_database_url(raw).startswith("postgresql+psycopg://")


def test_normalize_psycopg2_scheme() -> None:
    raw = "postgresql+psycopg2://user:pass@host:5432/db"
    assert _normalize_database_url(raw).startswith("postgresql+psycopg://")


def test_keep_sqlite_unchanged() -> None:
    raw = "sqlite+pysqlite:///./saastesa.db"
    assert _normalize_database_url(raw) == raw
