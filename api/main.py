from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

from database.database import get_connection
from database.queries import (
    get_all_events,
    get_recent_events,
    get_statistics,
    get_top_commands,
    get_top_sources,
    get_top_usernames,
)


app = FastAPI(
    title="Cloud Honeypot Monitoring API",
    description=(
        "REST API for accessing security events "
        "collected by the Cowrie honeypot."
    ),
    version="1.0.0",
)

# Dashboard (frontend/ folder) served at /dashboard

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app.mount(
    "/dashboard",
    StaticFiles(directory=FRONTEND_DIR, html=True),
    name="dashboard",
)

# Root endpoint

@app.get("/")
def root():
    """
    Basic API information.
    """

    return {
        "project": "Cloud Honeypot Monitoring System - FastAPI Backend",
        "status": "running",
        "documentation": "/docs",
        "dashboard": "/dashboard",
    }

# Health check

@app.get("/api/health")
def health_check():
    """
    Verify that the API and PostgreSQL database
    are reachable.
    """

    try:

        with get_connection() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    "SELECT 1;"
                )

                cursor.fetchone()

        return {
            "api": "online",
            "database": "online",
        }

    except Exception:

        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

# All events

@app.get("/api/events")
def events(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
):
    """
    Return security events.

    Pagination is provided using limit
    and offset.
    """

    try:

        records = get_all_events(
            limit=limit,
            offset=offset,
        )

        return {
            "count": len(records),
            "limit": limit,
            "offset": offset,
            "events": records,
        }

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve events",
        )

# Recent events

@app.get("/api/events/recent")
def recent_events(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    )
):
    """
    Return the newest honeypot events.
    """

    try:

        records = get_recent_events(
            limit=limit
        )

        return {
            "count": len(records),
            "events": records,
        }

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve recent events",
        )

# Statistics

@app.get("/api/statistics")
def statistics():
    """
    Return general honeypot statistics.
    """

    try:

        return get_statistics()

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve statistics",
        )

# Source IP statistics

@app.get("/api/sources")
def sources(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    )
):
    """
    Return the most active source IP addresses.
    """

    try:

        records = get_top_sources(
            limit=limit
        )

        return {
            "count": len(records),
            "sources": records,
        }

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve source statistics",
        )

# Username statistics

@app.get("/api/usernames")
def usernames(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    )
):
    """
    Return the most commonly observed usernames.
    """

    try:

        records = get_top_usernames(
            limit=limit
        )

        return {
            "count": len(records),
            "usernames": records,
        }

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve username statistics",
        )

# Command statistics

@app.get("/api/commands")
def commands(
    limit: int = Query(
        default=10,
        ge=1,
        le=100,
    )
):
    """
    Return the most commonly entered commands.
    """

    try:

        records = get_top_commands(
            limit=limit
        )

        return {
            "count": len(records),
            "commands": records,
        }

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve command statistics",
        )