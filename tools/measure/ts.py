"""UTC ISO timestamps with milliseconds, shared by the loggers."""
from datetime import datetime, timezone
def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
