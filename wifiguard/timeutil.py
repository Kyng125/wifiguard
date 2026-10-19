"""Time helpers. All timestamps are stored as UTC ISO-8601 strings with milliseconds.

Everything calls timeutil.now() so tests can freeze the clock.
"""
from datetime import datetime, timedelta, timezone


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    dt = dt or now()
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def ago(**kwargs) -> str:
    return iso(now() - timedelta(**kwargs))


def seconds_between(start: str, end: str) -> float:
    return (parse(end) - parse(start)).total_seconds()
