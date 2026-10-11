"""Async engine and session factory of the SQLite database."""

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.db_config import db_config
from app.db.virustotal_repository import VirusTotal

engine = create_async_engine(
    db_config.db_url, connect_args={"check_same_thread": False}
)
SessionLocal = async_sessionmaker(
    bind=engine, autocommit=False, autoflush=False, expire_on_commit=False
)


async def create_db_and_tables():
    """Create the tables of the ORM models that do not exist yet.

    Raises:
        sqlalchemy.exc.SQLAlchemyError: If the database cannot be reached or changed.
    """
    async with engine.begin() as conn:
        await conn.run_sync(VirusTotal.metadata.create_all)
