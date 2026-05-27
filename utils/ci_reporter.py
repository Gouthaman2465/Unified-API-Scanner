"""
utils/ci_reporter.py

Formats Aegis-API findings as GitHub Actions annotations
and determines pipeline pass/fail exit code.

Used only when running inside a CI environment.
"""

import os
import sys


# Severities ranked by numeric weight for threshold comparison
SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def is_ci_environment() -> bool:
    """
    Returns True if we are running inside a GitHub Actions runner.
    GitHub Actions always sets the CI environment variable to 'true'.
    """
    return os.environ.get("CI", "").lower() == "true"


def emit_annotation(finding: dict) -> None:
    """
    Prints a single finding as a GitHub Actions workflow command.

    GitHub Actions reads lines starting with '::' as commands.
    Format: ::level file=<path>,line=<n>::<message>

    Args:
        finding: A dict with keys: title, severity, owasp, protocol, description
    """
    severity = finding.get("severity", "informational").lower()
    title = finding.get("title", "Unknown Finding")
    protocol = finding.get("protocol", "unknown").upper()
    owasp = finding.get("owasp", "")
    description = finding.get("description", "")

    # Map our severity levels to GitHub annotation levels
    if severity in ("critical", "high"):
        level = "error"
    elif severity == "medium":
        level = "warning"
    else:
        level = "notice"

    message = f"[{protocol}] {title} | {owasp} | {description}"

    # This exact format is required by GitHub Actions
    print(f"::{level}::{message}")


def emit_summary(findings: list, protocol: str) -> None:
    """
    Prints a structured summary block to the GitHub Actions log.
    This appears in the job output, not as inline PR annotations.

    Args:
        findings: List of finding dicts from any scanner module
        protocol: Protocol label (REST / SOAP / GRAPHQL / ALL)
    """
    total = len(findings)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    for f in findings:
        sev = f.get("severity", "informational").lower()
        if sev in counts:
            counts[sev] += 1

    print("\n" + "=" * 60)
    print(f"AEGIS-API SCAN SUMMARY — Protocol: {protocol.upper()}")
    print("=" * 60)
    print(f"  Total findings : {total}")
    print(f"  Critical       : {counts['critical']}")
    print(f"  High           : {counts['high']}")
    print(f"  Medium         : {counts['medium']}")
    print(f"  Low            : {counts['low']}")
    print(f"  Informational  : {counts['informational']}")
    print("=" * 60 + "\n")


def evaluate_exit_code(findings: list, fail_threshold: str = "high") -> int:
    """
    Determines whether the pipeline should pass or fail.

    The pipeline fails (exit code 1) if any finding meets or exceeds
    the configured severity threshold.

    Args:
        findings: List of finding dicts
        fail_threshold: Minimum severity that causes pipeline failure.
                        Options: critical, high, medium, low
                        Default is 'high' — critical and high findings fail the build.

    Returns:
        0 if pipeline should pass, 1 if pipeline should fail
    """
    threshold_weight = SEVERITY_WEIGHT.get(fail_threshold.lower(), 3)

    for finding in findings:
        sev = finding.get("severity", "informational").lower()
        if SEVERITY_WEIGHT.get(sev, 0) >= threshold_weight:
            return 1  # Fail the pipeline

    return 0  # All findings below threshold — pipeline passes


def run_ci_report(findings: list, protocol: str, fail_threshold: str = "high") -> None:
    """
    Full CI reporting pipeline:
    1. Emit each finding as a GitHub annotation
    2. Print a summary block
    3. Exit with the correct code for the pipeline

    This function calls sys.exit() — call it only at the end of main().

    Args:
        findings: List of finding dicts from any scanner module
        protocol: Protocol label for the summary header
        fail_threshold: Severity level at which the pipeline should fail
    """
    if not is_ci_environment():
        # Not in CI — do nothing, let normal report generation handle output
        return

    # Step 1: Emit each finding as an inline annotation
    for finding in findings:
        emit_annotation(finding)

    # Step 2: Print summary to job log
    emit_summary(findings, protocol)

    # Step 3: Exit with appropriate code
    code = evaluate_exit_code(findings, fail_threshold)

    if code == 1:
        print(f"::error::Aegis-API pipeline gate FAILED — findings at or above '{fail_threshold}' threshold detected.")
    else:
        print(f"::notice::Aegis-API pipeline gate PASSED — no findings at or above '{fail_threshold}' threshold.")

    sys.exit(code)
