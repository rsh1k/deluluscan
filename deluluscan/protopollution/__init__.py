"""Client-side prototype-pollution detection (URL __proto__ -> Object.prototype)."""
from .engine import ProtoPollutionScan, ProtoResult, PLAYWRIGHT_HINT
from .payloads import vectors

__all__ = ["ProtoPollutionScan", "ProtoResult", "PLAYWRIGHT_HINT", "vectors"]
