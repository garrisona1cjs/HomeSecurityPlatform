import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================================================
# DB RETRY SAFETY (PREVENTS DROPPED CONNECTION CRASHES)
# =========================================================

from sqlalchemy.exc import OperationalError
import time

def safe_db_call(fn):
    for _ in range(3):
        try:
            return fn()
        except OperationalError:
            time.sleep(1)
    raise


# =========================================================
# DATABASE URL
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable not set")


# =========================================================
# DATABASE ENGINE
# =========================================================

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
)


# =========================================================
# SESSION FACTORY
# =========================================================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)


# =========================================================
# BASE MODEL
# =========================================================

Base = declarative_base()


# =========================================================
# FASTAPI DEPENDENCY
# =========================================================

def get_db():

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()