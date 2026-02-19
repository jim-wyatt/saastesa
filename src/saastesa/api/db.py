import os
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool

from saastesa.config import load_settings


def resolve_database_url() -> str:
    configured_url = os.getenv("TESA_DATABASE_URL", "").strip()
    if configured_url:
        return configured_url

    settings = load_settings()
    env = settings.environment.lower()
    if env in {"development", "local", "dev", "test"}:
        return "sqlite+pysqlite:///./saastesa.db"

    pg_user = os.getenv("TESA_DB_USER", "saastesa")
    pg_password = os.getenv("TESA_DB_PASSWORD", "saastesa")
    pg_host = os.getenv("TESA_DB_HOST", "localhost")
    pg_port = os.getenv("TESA_DB_PORT", "5432")
    pg_name = os.getenv("TESA_DB_NAME", "saastesa")
    return f"postgresql+psycopg://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_name}"


def create_db_engine(database_url: str) -> Engine:
    normalized_url = _normalize_database_url(database_url)

    if normalized_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if normalized_url.endswith(":memory:"):
            return create_engine(
                normalized_url,
                future=True,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        return create_engine(normalized_url, future=True, connect_args=connect_args)
    return create_engine(normalized_url, future=True)


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql+psycopg2://"):
        return database_url.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
    return database_url
