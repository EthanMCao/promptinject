"""PromptInject Lab. Original platform code, AGPL-3.0-or-later."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Preserve upstream byte-for-byte; import its pinned source through this adapter.
sys.path.insert(0, str(ROOT / "vendor/upstream/src"))
__version__ = "1.0.0"
