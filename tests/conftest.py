from pathlib import Path

import pytest

from dingdongditch import db, probes

NOWHERE = Path(__file__).parent / "no-such-folder" / "vulns.db"  # never created


@pytest.fixture(autouse=True)
def no_real_database(monkeypatch):
    """Point every test at a missing database, never at the real one."""
    monkeypatch.setenv(db.ENV_VAR, str(NOWHERE))


@pytest.fixture(autouse=True)
def short_retry_pause(monkeypatch):
    """Fake local servers aren't busy, so there's no need to wait before asking again."""
    monkeypatch.setattr(probes, "RETRY_PAUSE", 0.0)
