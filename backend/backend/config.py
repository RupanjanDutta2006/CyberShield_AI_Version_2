"""Backward-compatible config adapter for modules/tests importing `from backend.config import settings`."""
from app.core.config import settings, get_settings, Settings

__all__ = ["settings", "get_settings", "Settings"]

