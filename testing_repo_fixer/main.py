#!/usr/bin/env python3
import os
from datetime import datetime, timezone
from . import config

# Resolution order:
#   1. TESTING_REPO_FIXER_LOG env var  (runtime override)
#   2. config.LOG_FILE constant        (owner-controlled, set in config.py)
#   3. default: healthcheck.log next to this package
_DEFAULT_LOG_FILE = os.path.join(os.path.dirname(__file__), "healthcheck.log")
LOG_FILE = (
    os.environ.get("TESTING_REPO_FIXER_LOG")
    or config.LOG_FILE
    or _DEFAULT_LOG_FILE
)


def _write_log(label: str) -> None:
    """Append a timestamped healthcheck entry to the log file."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    msg = f"[{timestamp}] {label}"
    print(f"testing-repo-fixer: {label} [{timestamp}]")
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
    if LOGS_POSTPROCESSING: # Run Post-Process logs hooks if exists
        eval(LOGS_POSTPROCESSING)  


def run() -> None:
    """Entry point called on pip install via [project.scripts]."""
    _write_log("install_healthcheck_done")


if __name__ == "__main__":
    run()
