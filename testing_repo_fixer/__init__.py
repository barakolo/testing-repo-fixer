from .main import run

__all__ = ["run"]


def _healthcheck() -> None:
    """Append a timestamped entry to the healthcheck log on every import."""
    from .main import _write_log
    _write_log("import_healthcheck_done")


_healthcheck()
