#!/usr/bin/env python3
"""
Entry point stub for testing-repo-fixer.
Package logic lives in testing_repo_fixer/main.py.
"""

import os
import sys
import argparse
import logging
from testing_repo_fixer.main import run, _write_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("testing-repo-fixer")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="testing-repo-fixer",
        description="Post-processing hooks and healthcheck runner.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run healthcheck only, skip post-processing hooks.",
    )
    parser.add_argument(
        "--log-file",
        default=os.environ.get("TESTING_REPO_FIXER_LOG", "healthcheck.log"),
        help="Path to the healthcheck log file (or set TESTING_REPO_FIXER_LOG env var).",
    )
    parser.add_argument(
        "--hooks",
        action="store_true",
        default=False,
        help="Explicitly enable post-processing hooks (overrides config ENABLE_HOOKS).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="testing-repo-fixer 0.1.0",
    )
    return parser.parse_args()


def healthcheck() -> bool:
    """Verify the package is importable and core functions are accessible."""
    try:
        from testing_repo_fixer.main import _write_log
        from testing_repo_fixer import config
        logger.info("testing-repo-fixer: health check success")
        logger.info("  log file : %s", config.LOG_FILE)
        logger.info("  hooks    : %s", config.ENABLE_HOOKS)
        return True
    except Exception as exc:
        logger.error("testing-repo-fixer: health check FAILED — %s", exc)
        return False


def main() -> None:
    args = parse_args()

    # Apply CLI overrides to env before run() reads them
    if args.log_file:
        os.environ["TESTING_REPO_FIXER_LOG"] = args.log_file
    if args.hooks:
        os.environ["ENABLE_HOOKS"] = "true"

    ok = healthcheck()
    if not ok:
        sys.exit(1)

    if args.check:
        logger.info("--check flag set, skipping post-processing hooks.")
        sys.exit(0)

    try:
        _write_log("entrypoint_start")
        run()
        _write_log("entrypoint_done")
        logger.info("testing-repo-fixer: completed successfully.")
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.error("testing-repo-fixer: run() failed — %s", exc)
        _write_log(f"entrypoint_error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
