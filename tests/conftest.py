from pathlib import Path

import pytest

from dingdongditch import db

NOWHERE = Path(__file__).parent / "no-such-folder" / "vulns.db"  # never created


@pytest.fixture(autouse=True)
def no_real_database(monkeypatch):
    """Point every test at a missing database, never at the real one."""
    monkeypatch.setenv(db.ENV_VAR, str(NOWHERE))
