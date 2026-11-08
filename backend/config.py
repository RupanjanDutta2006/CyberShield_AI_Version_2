"""Backward-compatible config adapter for modules/tests importing `from backend.config import settings` or `import config`."""
import sys
from pathlib import Path

# Ensure app is on sys.path
backend_root = Path(__file__).resolve().parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from app.core.config import settings, get_settings, Settings

__all__ = ["settings", "get_settings", "Settings"]

