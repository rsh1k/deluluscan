"""Deluluscan attack-chain correlation: combine findings into higher-impact chains
and produce objectives for the agentic exploitation engine.

    from deluluscan.correlate import correlate, chain_findings, objectives
CLI: python3 -m deluluscan.correlate --results deluluscan-out/results.json
"""
from .engine import correlate, chain_findings, objectives, ChainSuggestion
from .chains import CHAIN_RULES

__all__ = ["correlate", "chain_findings", "objectives", "ChainSuggestion", "CHAIN_RULES"]
