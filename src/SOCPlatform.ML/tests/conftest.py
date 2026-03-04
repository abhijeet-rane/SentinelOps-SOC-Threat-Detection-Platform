"""Shared pytest fixtures for SOC ML tests."""
import sys
import os
import pytest

# Make the models package importable from tests/
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models.isolation_forest import LoginAnomalyDetector
from models.dbscan_ueba import UEBADetector
from models.zscore_network import NetworkOutlierDetector
from datetime import datetime, timezone


def make_ts(hour: int, minute: int = 0) -> str:
    """Create a UTC ISO timestamp for a given hour today."""
    now = datetime.now(timezone.utc)
    return now.replace(hour=hour, minute=minute, second=0, microsecond=0).isoformat()


@pytest.fixture(autouse=True)
def no_model_persistence(tmp_path, monkeypatch):
    """Redirect model saves to a temp dir so tests don't pollute disk."""
    import models.isolation_forest as _if
    import models.dbscan_ueba as _db
    import models.zscore_network as _zs
    monkeypatch.setattr(_if, "MODEL_DIR", str(tmp_path))
    monkeypatch.setattr(_db, "MODEL_DIR", str(tmp_path))
    monkeypatch.setattr(_zs, "MODEL_DIR", str(tmp_path))
