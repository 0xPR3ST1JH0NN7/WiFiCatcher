import pathlib
import sys

# Make the project root importable when running pytest from anywhere.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def reset_session_state():
    """The API keeps a process-wide graph singleton; reset it between tests."""
    from wifihound.api import routes
    from wifihound.graph import WifiGraph

    routes.STATE = WifiGraph()
    yield
    routes.STATE = WifiGraph()
