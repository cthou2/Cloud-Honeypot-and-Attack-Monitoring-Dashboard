import csv
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from database.database import (
    create_tables,
    get_event_count,
    get_unique_source_count,
    insert_events,
)

# File locations

LOG_FILE = Path(
    "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json"
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"

CSV_FILE = DATA_DIR / "events.csv"

# Helper functions

def clean_value(value):
    """
    Convert empty strings into None.
    """

    if value == "":
        return None

    return value


def safe_int(value):
    """
    Convert a value to an integer when possible.
    Returns None when the value does not exist or cannot
    safely be converted.
    """

    if value is None or value == "":
        return None

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


def parse_timestamp(value):
    """
    Convert Cowrie's ISO timestamp into a Python datetime.
    """

    if not value:
        return None

    try:

        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    except ValueError:

        return None

# Load Cowrie JSON

def load_events(log_file):
    """
    Load Cowrie events from cowrie.json.
    Cowrie stores one JSON object per line.
    """

    events = []

    with log_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            try:

                event = json.loads(line)

                events.append(event)

            except json.JSONDecodeError:

                print(
                    f"Warning: invalid JSON "
                    f"on line {line_number}. "
                    f"Skipping event."
                )

    return events

# Generate unique event hash

def create_event_hash(event):
    """
    Create a SHA-256 fingerprint from the original Cowrie event.
    The same Cowrie event will always generate the
    same hash.
    PostgreSQL uses this hash to prevent duplicate rows.
    """

    event_json = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(
        event_json.encode("utf-8")
    ).hexdigest()

# Normalize Cowrie event

def normalize_event(event):
    """
    Convert Cowrie events into one consistent structure
    that can be exported to CSV and stored in PostgreSQL.
    """

    return {
        "event_hash":
            create_event_hash(event),

        "timestamp":
            parse_timestamp(
                event.get("timestamp")
            ),

        "event_type":
            clean_value(
                event.get("eventid")
            ),

        "session_id":
            clean_value(
                event.get("session")
            ),

        "source_ip":
            clean_value(
                event.get("src_ip")
            ),

        "source_port":
            safe_int(
                event.get("src_port")
            ),

        "destination_ip":
            clean_value(
                event.get("dst_ip")
            ),

        "destination_port":
            safe_int(
                event.get("dst_port")
            ),

        "protocol":
            clean_value(
                event.get("protocol")
            ),

        "username":
            clean_value(
                event.get("username")
            ),

        "command":
            clean_value(
                event.get("input")
            ),

        "message":
            clean_value(
                event.get("message")
            ),
    }

# General statistics

def show_statistics(events):
    """
    Display general Cowrie activity statistics.
    """

    event_types = Counter()
    source_ips = Counter()
    usernames = Counter()

    for event in events:

        event_type = event.get("event_type")
        source_ip = event.get("source_ip")
        username = event.get("username")

        if event_type:
            event_types[event_type] += 1

        if source_ip:
            source_ips[source_ip] += 1

        if username:
            usernames[username] += 1

    print("\n================================")
    print("     HONEYPOT STATISTICS")
    print("================================")

    print(
        f"\nTotal events: "
        f"{len(events)}"
    )

    print(
        f"Unique source IPs: "
        f"{len(source_ips)}"
    )

    print("\nTop Event Types:")

    if event_types:

        for event_type, count in (
            event_types.most_common(10)
        ):

            print(
                f"  {event_type}: {count}"
            )

    else:

        print(
            "  No event types recorded yet."
        )

    print("\nTop Source IPs:")

    if source_ips:

        for source_ip, count in (
            source_ips.most_common(10)
        ):

            print(
                f"  {source_ip}: {count}"
            )

    else:

        print(
            "  No source IP addresses recorded yet."
        )

    print("\nTop Usernames:")

    if usernames:

        for username, count in (
            usernames.most_common(10)
        ):

            print(
                f"  {username}: {count}"
            )

    else:

        print(
            "  No usernames recorded yet."
        )

# Login statistics

def show_login_statistics(events):
    """
    Display both successful and failed Cowrie
    authentication events.
    """

    successful_logins = [
        event
        for event in events
        if event.get("event_type")
        == "cowrie.login.success"
    ]

    failed_logins = [
        event
        for event in events
        if event.get("event_type")
        == "cowrie.login.failed"
    ]

    successful_usernames = Counter(
        event["username"]
        for event in successful_logins
        if event.get("username")
    )

    failed_usernames = Counter(
        event["username"]
        for event in failed_logins
        if event.get("username")
    )

    print("\n================================")
    print("       LOGIN ANALYSIS")
    print("================================")

    print(
        f"\nSuccessful honeypot logins: "
        f"{len(successful_logins)}"
    )

    print("\nAccepted Usernames:")

    if successful_usernames:

        for username, count in (
            successful_usernames.most_common(10)
        ):

            print(
                f"  {username}: {count}"
            )

    else:

        print(
            "  No successful honeypot "
            "logins recorded yet."
        )

    print(
        f"\nFailed honeypot logins: "
        f"{len(failed_logins)}"
    )

    print("\nFailed Usernames:")

    if failed_usernames:

        for username, count in (
            failed_usernames.most_common(10)
        ):

            print(
                f"  {username}: {count}"
            )

    else:

        print(
            "  No failed usernames "
            "recorded yet."
        )

# Command statistics

def show_command_statistics(events):
    """
    Display commands entered inside Cowrie's
    simulated shell.
    """

    commands = Counter(
        event["command"]
        for event in events
        if event.get("command")
    )

    print("\n================================")
    print("       COMMAND ANALYSIS")
    print("================================")

    if commands:

        print()

        for command, count in (
            commands.most_common(10)
        ):

            print(
                f"  {command}: {count}"
            )

    else:

        print(
            "\nNo commands recorded yet."
        )

# CSV export

def export_to_csv(events):
    """
    Export normalized Cowrie events to CSV.
    The CSV is mainly useful for debugging and
    manually inspecting data.
    PostgreSQL is now the primary storage system.
    """

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    fields = [
        "event_hash",
        "timestamp",
        "event_type",
        "session_id",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "username",
        "command",
        "message",
    ]

    with CSV_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()

        writer.writerows(events)

    print("\nCSV exported to:")

    print(CSV_FILE)


def main():

    print("\n================================")
    print("     COWRIE LOG PROCESSOR")
    print("================================")

    if not LOG_FILE.exists():

        print(
            "\nERROR: Cowrie log was not found."
        )

        print(LOG_FILE)

        return

    try:

        raw_events = load_events(
            LOG_FILE
        )

    except PermissionError:

        print(
            "\nERROR: The student account "
            "cannot read Cowrie's log."
        )

        print(
            "Check the honeypot group "
            "permissions."
        )

        return

    events = [
        normalize_event(event)
        for event in raw_events
    ]

    print(
        f"\nSuccessfully loaded "
        f"{len(events)} Cowrie events."
    )

    show_statistics(events)

    show_login_statistics(events)

    show_command_statistics(events)

    export_to_csv(events)

    try:

        create_tables()

        inserted, duplicates = (
            insert_events(events)
        )

        database_count = (
            get_event_count()
        )

        database_sources = (
            get_unique_source_count()
        )

        print("\n================================")
        print("       DATABASE IMPORT")
        print("================================")

        print(
            f"\nNew events inserted: "
            f"{inserted}"
        )

        print(
            f"Duplicate events skipped: "
            f"{duplicates}"
        )

        print(
            f"Total database events: "
            f"{database_count}"
        )

        print(
            f"Unique database sources: "
            f"{database_sources}"
        )

    except Exception as error:

        print("\n================================")
        print("       DATABASE ERROR")
        print("================================")

        print(
            "\nThe Cowrie logs were processed, "
            "but PostgreSQL failed."
        )

        print("\nError:")

        print(error)


if __name__ == "__main__":
    main()