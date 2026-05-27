# utils/logger.py

import csv
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# CONSOLE LOGGING
# ---------------------------------------------------------------------------

def log_event(event_type: str, *details):
    """
    Flexible console logging function used across all modules.

    Example:
        log_event("INFO", "Server started")
        log_event("HTTP", url, status, "Request successful")
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detail_text = " | ".join(str(d) for d in details)
    print(f"[{timestamp}] [{event_type}] {detail_text}")


def info(message: str):
    log_event("INFO", message)


def warn(message: str):
    log_event("WARN", message)


def error(message: str):
    log_event("ERROR", message)


def success(message: str):
    log_event("SUCCESS", message)


# ---------------------------------------------------------------------------
# AUDIT LOG (CSV)
# ---------------------------------------------------------------------------

def log_finding(finding: dict, filename: str = "audit_log.csv") -> None:
    """
    Append a confirmed vulnerability finding to the CSV audit log.

    Called by scanner modules after a finding is confirmed so every
    vulnerability has a permanent log entry regardless of whether the
    PDF report is generated.

    Handles both finding dict shapes:
      - Older modules use 'type' and 'url' keys
      - Phase 7+ modules use 'title' and 'target_url' keys

    Args:
        finding  : Finding dict produced by any scanner module
        filename : Path to the CSV audit log (default: audit_log.csv)
    """
    file_exists = os.path.isfile(filename)

    # Normalise keys across old and new finding shapes
    url   = finding.get("url") or finding.get("target_url", "N/A")
    title = finding.get("type") or finding.get("title", "Unknown Finding")

    row = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        finding.get("protocol", "N/A"),
        title,
        url,
        finding.get("owasp", "N/A"),
        str(finding.get("cvss", "N/A")),
        str(finding.get("confidence_score", "N/A")),
    ]

    try:
        with open(filename, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    "Timestamp", "Protocol", "Finding",
                    "URL", "OWASP", "CVSS", "Confidence"
                ])
            writer.writerow(row)
    except IOError as e:
        error(f"Failed to write finding to audit log: {e}")
