"""
SentinelAI Database Initialization

Creates all SQLAlchemy tables in the configured database.
"""

from database.session import engine, Base
from database import models


def init_database():
    print("=" * 60)
    print("       SENTINELAI DATABASE INITIALIZATION")
    print("=" * 60)

    print("\nCreating database tables...")

    Base.metadata.create_all(bind=engine)

    print("\nDatabase tables created successfully.")

    print("\nTables:")
    for table in Base.metadata.sorted_tables:
        print(f"  - {table.name}")

    print("\n" + "=" * 60)
    print("             DATABASE READY")
    print("=" * 60)


if __name__ == "__main__":
    init_database()