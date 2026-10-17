from psycopg.rows import dict_row

from database.database import get_connection


def get_all_events(limit=100, offset=0):
    """
    Return security events from PostgreSQL.

    Results are ordered with the newest
    events first.
    """

    sql = """
    SELECT
        id,
        event_hash,
        timestamp,
        event_type,
        session_id,
        source_ip::text AS source_ip,
        source_port,
        destination_ip::text AS destination_ip,
        destination_port,
        protocol,
        username,
        command,
        message,
        created_at
    FROM security_events
    ORDER BY timestamp DESC NULLS LAST
    LIMIT %s
    OFFSET %s;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (limit, offset)
            )

            return cursor.fetchall()


def get_recent_events(limit=20):
    """
    Return the newest security events.
    """

    sql = """
    SELECT
        id,
        timestamp,
        event_type,
        source_ip::text AS source_ip,
        source_port,
        destination_port,
        username,
        command,
        message
    FROM security_events
    ORDER BY timestamp DESC NULLS LAST
    LIMIT %s;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (limit,)
            )

            return cursor.fetchall()


def get_statistics():
    """
    Return general honeypot statistics.
    """

    sql = """
    SELECT

        COUNT(*) AS total_events,

        COUNT(
            DISTINCT source_ip
        ) AS unique_sources,

        COUNT(*) FILTER (
            WHERE event_type =
            'cowrie.login.success'
        ) AS successful_logins,

        COUNT(*) FILTER (
            WHERE event_type =
            'cowrie.login.failed'
        ) AS failed_logins,

        COUNT(*) FILTER (
            WHERE command IS NOT NULL
        ) AS commands

    FROM security_events;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(sql)

            return cursor.fetchone()


def get_top_sources(limit=10):
    """
    Return the source IP addresses generating
    the most Cowrie events.
    """

    sql = """
    SELECT
        source_ip::text AS source_ip,
        COUNT(*) AS event_count
    FROM security_events
    WHERE source_ip IS NOT NULL
    GROUP BY source_ip
    ORDER BY event_count DESC
    LIMIT %s;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (limit,)
            )

            return cursor.fetchall()


def get_top_usernames(limit=10):
    """
    Return the most commonly observed usernames.
    """

    sql = """
    SELECT
        username,
        COUNT(*) AS attempt_count
    FROM security_events
    WHERE username IS NOT NULL
    GROUP BY username
    ORDER BY attempt_count DESC
    LIMIT %s;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (limit,)
            )

            return cursor.fetchall()


def get_top_commands(limit=10):
    """
    Return the most commonly entered commands.
    """

    sql = """
    SELECT
        command,
        COUNT(*) AS command_count
    FROM security_events
    WHERE command IS NOT NULL
    GROUP BY command
    ORDER BY command_count DESC
    LIMIT %s;
    """

    with get_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (limit,)
            )

            return cursor.fetchall()