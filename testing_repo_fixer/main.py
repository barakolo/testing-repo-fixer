#!/usr/bin/env python3
import os
from datetime import datetime, timezone

# Override log file location by setting this env var, e.g.:
#   TESTING_REPO_FIXER_LOG=~/logs/my_healthcheck.log
_DEFAULT_LOG_FILE = os.path.join(os.path.dirname(__file__), "healthcheck.log")
LOG_FILE = os.environ.get("TESTING_REPO_FIXER_LOG", _DEFAULT_LOG_FILE)


def _write_log(label: str) -> None:
    """Append a timestamped healthcheck entry to the log file."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    msg = f"[{timestamp}] {label}"
    print(f"testing-repo-fixer: {label} [{timestamp}]")
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")


def run() -> None:
    """Entry point called on pip install via [project.scripts]."""
    _write_log("install_healthcheck_done")


if __name__ == "__main__":
    run()
