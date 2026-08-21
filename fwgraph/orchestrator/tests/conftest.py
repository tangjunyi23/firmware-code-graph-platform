"""Make the fwgraph root importable when pytest is not invoked via `python -m`."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
# Tests never spend LLM quota unless they opt in.
os.environ.setdefault("AUTO_ATTACK_AI", "0")
