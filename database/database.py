import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

# Project / environment configuration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)

# Database connection

def get_connection():
    """
    Create a connection to the PostgreSQL database.
    Database credentials are loaded from the .env file.
    """

    return psycopg.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )

# Database table creation

def create_tables():
    """
    Create the database tables needed by the honeypot
    monitoring application.
    IF NOT EXISTS prevents PostgreSQL from recreating the
    table every time the program runs.
    """

    create_security_events_table = """
    CREATE TABLE IF NOT EXISTS security_events (
        id BIGSERIAL PRIMARY KEY,

        event_hash VARCHAR(64)
            UNIQUE
            NOT NULL,

        timestamp TIMESTAMPTZ,

        event_type TEXT
            NOT NULL,

        session_id TEXT,

        source_ip INET,

        source_port INTEGER,

        destination_ip INET,

        destination_port INTEGER,

        protocol TEXT,

        username TEXT,

        command TEXT,

        message TEXT,

        created_at TIMESTAMPTZ
            DEFAULT CURRENT_TIMESTAMP
    );
    """

    create_timestamp_index = """
    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
    ON security_events(timestamp);
    """

    create_event_type_index = """
    CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events(event_type);
    """

    create_source_ip_index = """
    CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
    ON security_events(source_ip);
    """

    with get_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(create_security_events_table)
            cursor.execute(create_timestamp_index)
            cursor.execute(create_event_type_index)
            cursor.execute(create_source_ip_index)

# Insert multiple Cowrie events

def insert_events(events):
    """
    Insert normalized Cowrie events into PostgreSQL.

    event_hash is UNIQUE, so running the parser multiple
    times will not duplicate events already in the database.

    Returns:
        inserted   -> number of new events stored
        duplicates -> number of existing events skipped
    """

    sql = """
    INSERT INTO security_events (
        event_hash,
        timestamp,
        event_type,
        session_id,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        username,
        command,
        message
    )
    VALUES (
        %(event_hash)s,
        %(timestamp)s,
        %(event_type)s,
        %(session_id)s,
        %(source_ip)s,
        %(source_port)s,
        %(destination_ip)s,
        %(destination_port)s,
        %(protocol)s,
        %(username)s,
        %(command)s,
        %(message)s
    )
    ON CONFLICT (event_hash)
    DO NOTHING
    RETURNING id;
    """

    inserted = 0
    duplicates = 0

    with get_connection() as connection:

        with connection.cursor() as cursor:

            for event in events:

                cursor.execute(sql, event)

                result = cursor.fetchone()

                if result is not None:
                    inserted += 1
                else:
                    duplicates += 1

    return inserted, duplicates

# Database statistics

def get_event_count():
    """
    Return the total number of security events currently
    stored in PostgreSQL.
    """

    sql = """
    SELECT COUNT(*)
    FROM security_events;
    """

    with get_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(sql)

            result = cursor.fetchone()

    return result[0]


def get_unique_source_count():
    """
    Return the number of unique source IP addresses stored
    in PostgreSQL.
    """

    sql = """
    SELECT COUNT(DISTINCT source_ip)
    FROM security_events
    WHERE source_ip IS NOT NULL;
    """

    with get_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(sql)

            result = cursor.fetchone()

    return result[0]

# Direct database.py test

if __name__ == "__main__":

    try:

        create_tables()

        print("Successfully connected to PostgreSQL.")
        print("Database tables are ready.")

        event_count = get_event_count()

        print(
            f"Current number of stored events: "
            f"{event_count}"
        )

    except Exception as error:

        print("Database setup failed:")
        print(error)