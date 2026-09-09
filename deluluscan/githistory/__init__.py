"""Secret scanning across git history (catches secrets removed from HEAD)."""
from .engine import GitSecretScan

__all__ = ["GitSecretScan"]
