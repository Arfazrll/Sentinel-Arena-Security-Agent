"""Resilience audit report generation (HTML / Markdown / PDF)."""

from .generator import build_html, build_markdown, build_pdf, write_report

__all__ = ["build_html", "build_markdown", "build_pdf", "write_report"]
