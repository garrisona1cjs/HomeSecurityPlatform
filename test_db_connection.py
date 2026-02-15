import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

print("Connecting to database...\n")

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    print("✅ Connected successfully!\n")

    print("PostgreSQL version:")
    version = conn.execute(text("SELECT version();"))
    for row in version:
        print(row[0])

    print("\nTables in public schema:")
    tables = conn.execute(text("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema='public';
    """))

    found = False
    for table in tables:
        print(" -", table[0])
        found = True

    if not found:
        print("⚠️ No tables found.")
