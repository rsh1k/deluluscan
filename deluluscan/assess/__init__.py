"""Deluluscan unified assessment: run the modules, merge findings, export LOCAL
reports in multiple formats (JSON, Markdown, self-contained HTML, CSV, XLSX,
JUnit, SARIF). No online publishing.

    from deluluscan.assess import Assessment, run_web_assessment, write_reports
CLI: python3 -m deluluscan.assess --url http://127.0.0.1:8080/ --formats md,html,json,sarif
"""
from .runner import Assessment, run_web_assessment, dedup
from .report import write_reports, to_markdown, to_html

__all__ = ["Assessment", "run_web_assessment", "dedup",
           "write_reports", "to_markdown", "to_html"]
