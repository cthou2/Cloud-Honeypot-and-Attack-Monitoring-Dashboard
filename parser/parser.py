import csv
import json
from collections import Counter
from pathlib import Path


# Cowrie owns this log.
LOG_FILE = Path(
    "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json"
)

# Find our project automatically.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

CSV_FILE = DATA_DIR / "events.csv"


def load_events(log_file):
    """Load JSON events from Cowrie's JSON-lines log."""

    events = []

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)

            except json.JSONDecodeError:
                print(
                    f"Warning: skipping invalid JSON "
                    f"on line {line_number}"
                )

    return events


def normalize_event(event):
    """
    Convert different Cowrie event types into one
    consistent structure for our application.
    """

    return {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("eventid"),
        "session_id": event.get("session"),
        "source_ip": event.get("src_ip"),
        "source_port": event.get("src_port"),
        "destination_ip": event.get("dst_ip"),
        "destination_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "username": event.get("username"),
        "command": event.get("input"),
        "message": event.get("message"),
    }


def show_statistics(events):
    """Display basic honeypot statistics."""

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

    print(f"\nTotal events: {len(events)}")
    print(f"Unique source IPs: {len(source_ips)}")

    print("\nTop Event Types:")

    for event_type, count in event_types.most_common(10):
        print(f"  {event_type}: {count}")

    print("\nTop Source IPs:")

    for source_ip, count in source_ips.most_common(10):
        print(f"  {source_ip}: {count}")

    print("\nTop Usernames:")

    if usernames:

        for username, count in usernames.most_common(10):
            print(f"  {username}: {count}")

    else:

        print("  No username attempts recorded yet.")


def show_login_statistics(events):
    """Analyze failed Cowrie login attempts."""

    failed_logins = [
        event
        for event in events
        if event.get("event_type") == "cowrie.login.failed"
    ]

    usernames = Counter(
        event["username"]
        for event in failed_logins
        if event.get("username")
    )

    print("\n================================")
    print("       LOGIN ANALYSIS")
    print("================================")

    print(
        f"\nFailed login attempts: "
        f"{len(failed_logins)}"
    )

    print("\nMost Attempted Usernames:")

    if usernames:

        for username, count in usernames.most_common(10):
            print(f"  {username}: {count}")

    else:

        print("  No failed usernames recorded yet.")


def show_command_statistics(events):
    """Display commands entered into Cowrie."""

    commands = Counter(
        event["command"]
        for event in events
        if event.get("command")
    )

    print("\n================================")
    print("       COMMAND ANALYSIS")
    print("================================")

    if commands:

        for command, count in commands.most_common(10):
            print(f"  {command}: {count}")

    else:

        print("\nNo commands recorded yet.")


def export_to_csv(events):
    """Export normalized events for inspection."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    fields = [
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

    print(f"\nCSV exported to:")
    print(CSV_FILE)


def main():

    if not LOG_FILE.exists():

        print("ERROR: Cowrie log was not found.")
        print(LOG_FILE)
        return

    try:

        raw_events = load_events(LOG_FILE)

    except PermissionError:

        print("ERROR: student cannot read the Cowrie log.")
        print("Check the honeypot group permissions.")
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


if __name__ == "__main__":
    main()