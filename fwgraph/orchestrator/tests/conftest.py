"""Make the fwgraph root importable when pytest is not invoked via `python -m`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
