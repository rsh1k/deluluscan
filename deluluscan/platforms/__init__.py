"""Platform intelligence: fingerprint a target and understand its architecture.

Detects the platform (WordPress, Drupal, Joomla, Ghost, cloud hosting), then
surfaces what that platform's API/auth/sensitive surface means for testing.
"""
from .profiles import PROFILES, PlatformProfile, Signal, profile_by_name
from .engine import PlatformScan, Detection

__all__ = ["PROFILES", "PlatformProfile", "Signal", "profile_by_name",
           "PlatformScan", "Detection"]
