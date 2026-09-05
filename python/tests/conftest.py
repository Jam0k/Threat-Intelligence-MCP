import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_driver import FIXTURES, ROOT  # noqa: E402


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def spec() -> dict:
    return json.loads((ROOT / "tools" / "tools.json").read_text(encoding="utf-8"))


@pytest.fixture
def tmp_home(tmp_path: Path) -> Path:
    (tmp_path / "xdg").mkdir()
    return tmp_path
