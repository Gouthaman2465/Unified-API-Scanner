"""
utils/reporting.py

Unified PDF report generator for Aegis-API.
Produces a professional five-section VAPT report
covering REST, SOAP, and GraphQL findings.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle,
    Spacer, PageBreak, HRFlowable, Preformatted
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm

# ─────────────────────────────────────────────────────────────
# SEVERITY COLOUR MAP
# Used by findings tables and severity badges throughout report
# ─────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "Critical": colors.HexColor("#D32F2F"),
    "High":     colors.HexColor("#F57C00"),
    "Medium":   colors.HexColor("#FBC02D"),
    "Low":      colors.HexColor("#388E3C"),
    "Info":     colors.HexColor("#1976D2"),
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# ─────────────────────────────────────────────────────────────
# OWASP API TOP 10 REFERENCE TABLE
# Maps OWASP category ID to full name for report display
# ─────────────────────────────────────────────────────────────
OWASP_NAMES = {
    "API1":  "Broken Object Level Authorization (BOLA/IDOR)",
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API4":  "Unrestricted Resource Consumption",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Unrestricted Access to Sensitive Business Flows",
    "API7":  "Server Side Request Forgery",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}


def _build_styles():
    """
    Build and return all paragraph styles used in the report.
    Centralising styles here avoids repetition across sections.
    """
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=colors.HexColor("#1A237E"),
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=11,
            textColor=colors.grey,
            spaceAfter=12,
        ),
        "section_header": ParagraphStyle(
            "SectionHeader",
            parent=base["Heading1"],
            fontSize=14,
            textColor=colors.HexColor("#1A237E"),
            borderPad=4,
            spaceBefore=18,
            spaceAfter=6,
        ),
        "subsection_header": ParagraphStyle(
            "SubsectionHeader",
            parent=base["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#37474F"),
            spaceBefore=12,
            spaceAfter=4,
        ),
        "body": base["Normal"],
        "code": ParagraphStyle(
            "CodeBlock",
            parent=base["Code"],
            fontSize=8,
            backColor=colors.HexColor("#F5F5F5"),
            borderColor=colors.HexColor("#E0E0E0"),
            borderWidth=1,
            borderPad=6,
            fontName="Courier",
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["Heading3"],
            fontSize=11,
            textColor=colors.HexColor("#B71C1C"),
            spaceBefore=14,
            spaceAfter=4,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#546E7A"),
            fontName="Helvetica-Bold",
        ),
    }
    return styles


def _severity_count(findings):
    """
    Count findings by severity level.
    Returns a dict: {"Critical": 2, "High": 1, ...}
    """
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "Info")
        if sev in counts:
            counts[sev] += 1
    return counts


def _protocol_count(findings):
    """
    Count findings by protocol.
    Returns a dict: {"REST": 3, "SOAP": 2, "GraphQL": 1}
    """
    counts = {}
    for f in findings:
        proto = f.get("protocol", "Unknown")
        counts[proto] = counts.get(proto, 0) + 1
    return counts


def _overall_risk(sev_counts):
    """
    Determine overall risk rating from severity distribution.
    Logic: highest severity present with at least 1 finding wins.
    """
    for level in SEVERITY_ORDER:
        if sev_counts.get(level, 0) > 0:
            return level
    return "Info"


# ─────────────────────────────────────────────────────────────
# SECTION 1 — EXECUTIVE SUMMARY
# ─────────────────────────────────────────────────────────────

def build_executive_summary(findings, target_urls, styles):
    """
    Build flowables for the Executive Summary section.
    Audience: management. No raw HTTP here — plain English only.

    Args:
        findings: list of finding dicts from all scanner modules
        target_urls: dict mapping protocol to URL tested
        styles: dict of ParagraphStyles

    Returns:
        list of ReportLab flowables
    """
    story = []

    story.append(Paragraph("SECTION 1 — EXECUTIVE SUMMARY", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.3*cm))

    sev_counts = _severity_count(findings)
    proto_counts = _protocol_count(findings)
    overall = _overall_risk(sev_counts)
    total = len(findings)

    # Overall risk statement
    risk_color = SEVERITY_COLORS.get(overall, colors.grey)
    summary_text = (
        f"Aegis-API completed a unified API security assessment covering "
        f"<b>{', '.join(target_urls.keys())}</b> API protocols. "
        f"A total of <b>{total} vulnerabilities</b> were identified. "
        f"The overall risk rating for this assessment is: "
        f"<font color='#{risk_color.hexval().upper()}'><b>{overall}</b></font>."
    )
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 0.4*cm))

    # Severity breakdown table
    story.append(Paragraph("Vulnerability Distribution by Severity", styles["subsection_header"]))
    sev_data = [["Severity", "Count", "Risk Level"]]
    for sev in SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        sev_data.append([sev, str(count), "Immediate action required" if sev == "Critical"
                         else "Fix within sprint" if sev == "High"
                         else "Fix within quarter" if sev == "Medium"
                         else "Best effort" if sev == "Low"
                         else "Informational"])

    sev_table = Table(sev_data, colWidths=[4*cm, 3*cm, 9*cm])
    sev_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ])
    # Colour each severity row's first cell
    for i, sev in enumerate(SEVERITY_ORDER, start=1):
        sev_style.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS.get(sev, colors.black))
        sev_style.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")

    sev_table.setStyle(sev_style)
    story.append(sev_table)
    story.append(Spacer(1, 0.4*cm))

    # Protocol breakdown table
    story.append(Paragraph("Vulnerability Distribution by Protocol", styles["subsection_header"]))
    proto_data = [["Protocol", "Findings", "Target URL"]]
    for proto, url in target_urls.items():
        proto_data.append([proto, str(proto_counts.get(proto, 0)), url])

    proto_table = Table(proto_data, colWidths=[3*cm, 3*cm, 10*cm])
    proto_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(proto_table)
    story.append(Spacer(1, 0.4*cm))

    # Key recommendations in plain English
    story.append(Paragraph("Key Recommendations", styles["subsection_header"]))
    recommendations = _generate_recommendations(findings)
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["body"]))
        story.append(Spacer(1, 0.1*cm))

    story.append(PageBreak())
    return story


def _generate_recommendations(findings):
    """
    Derive top 5 plain-English recommendations from finding data.
    Filters for highest-severity findings and maps them to actions.
    """
    recs = []
    seen_owasp = set()

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "Info"))
    )

    for f in sorted_findings:
        owasp = f.get("owasp_id", "")
        if owasp not in seen_owasp:
            seen_owasp.add(owasp)
            proto = f.get("protocol", "API")
            sev = f.get("severity", "")
            title = f.get("title", "Unknown vulnerability")
            recs.append(
                f"[{sev}] Remediate <b>{title}</b> in the {proto} layer "
                f"— maps to {owasp}: {OWASP_NAMES.get(owasp, 'Unknown')}."
            )
        if len(recs) >= 5:
            break

    if not recs:
        recs.append("No actionable findings detected. Maintain current security posture.")

    return recs


# ─────────────────────────────────────────────────────────────
# SECTION 2 — SCOPE AND METHODOLOGY
# ─────────────────────────────────────────────────────────────

def build_scope_and_methodology(target_urls, scan_date, styles):
    """
    Build the Scope and Methodology section.
    Documents what was tested, when, and how each protocol was approached.
    """
    story = []

    story.append(Paragraph("SECTION 2 — SCOPE AND METHODOLOGY", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph(
        f"Assessment Date: <b>{scan_date}</b>", styles["body"]
    ))
    story.append(Spacer(1, 0.2*cm))

    # Target URL table
    story.append(Paragraph("Target Scope", styles["subsection_header"]))
    url_data = [["Protocol", "Target URL", "Discovery Method"]]
    discovery_methods = {
        "REST":    "OpenAPI/Swagger endpoint enumeration",
        "SOAP":    "WSDL parsing at ?wsdl suffix",
        "GraphQL": "Introspection query to /graphql",
    }
    for proto, url in target_urls.items():
        url_data.append([proto, url, discovery_methods.get(proto, "Manual")])

    url_table = Table(url_data, colWidths=[3*cm, 7*cm, 6*cm])
    url_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    story.append(url_table)
    story.append(Spacer(1, 0.4*cm))

    # Methodology per protocol
    story.append(Paragraph("Testing Methodology by Protocol", styles["subsection_header"]))

    methodology = {
        "REST": [
            "Endpoint discovery via Swagger/OpenAPI parser",
            "IDOR/BOLA testing via ID fuzzing with response diffing",
            "Mass assignment via PUT injection with state verification",
            "Rate limit detection via burst request analysis",
            "JWT token analysis for algorithm confusion and missing claims",
        ],
        "SOAP": [
            "WSDL enumeration and operation discovery",
            "XML External Entity (XXE) injection via payload templates",
            "XML injection and CDATA escape bypass testing",
            "WS-Security header presence and authentication bypass",
            "SOAPAction spoofing and header manipulation",
        ],
        "GraphQL": [
            "Schema discovery via introspection query",
            "Field-level authorization bypass on sensitive fields",
            "Query depth attack (depth bomb) with resource exhaustion measurement",
            "Batch abuse and alias-based rate limit bypass testing",
            "JWT analysis on Authorization header (same module as REST)",
        ],
    }

    for proto, steps in methodology.items():
        if proto in target_urls:
            story.append(Paragraph(f"{proto} API", styles["label"]))
            for step in steps:
                story.append(Paragraph(f"• {step}", styles["body"]))
            story.append(Spacer(1, 0.2*cm))

    # OWASP coverage table
    story.append(Paragraph("OWASP API Top 10 Coverage Matrix", styles["subsection_header"]))
    owasp_data = [["OWASP ID", "Category", "REST", "SOAP", "GraphQL"]]
    coverage_map = {
        "API1":  {"REST": "✓ IDOR/BOLA",       "SOAP": "—",                "GraphQL": "✓ Field auth"},
        "API2":  {"REST": "✓ JWT",              "SOAP": "✓ WS-Security",   "GraphQL": "✓ JWT"},
        "API3":  {"REST": "✓ Mass Assignment",  "SOAP": "—",                "GraphQL": "✓ Mutation inject"},
        "API4":  {"REST": "✓ Rate limit",       "SOAP": "—",                "GraphQL": "✓ Depth + Batch"},
        "API7":  {"REST": "—",                  "SOAP": "✓ XXE/SSRF",      "GraphQL": "—"},
        "API8":  {"REST": "—",                  "SOAP": "✓ WSDL exposure",  "GraphQL": "✓ Introspection"},
    }
    for owasp_id, protos in coverage_map.items():
        owasp_data.append([
            owasp_id,
            OWASP_NAMES.get(owasp_id, "")[:40] + "...",
            protos.get("REST", "—"),
            protos.get("SOAP", "—"),
            protos.get("GraphQL", "—"),
        ])

    owasp_table = Table(owasp_data, colWidths=[2*cm, 5.5*cm, 3*cm, 3*cm, 3*cm])
    owasp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
    ]))
    story.append(owasp_table)
    story.append(PageBreak())
    return story


# ─────────────────────────────────────────────────────────────
# SECTION 3 — DETAILED FINDINGS
# ─────────────────────────────────────────────────────────────

def build_detailed_findings(findings, styles):
    """
    Build one detailed finding block per vulnerability.
    Each block includes: title, protocol, OWASP, CVSS, description,
    reproduction steps, protocol-appropriate evidence, and remediation.
    """
    story = []

    story.append(Paragraph("SECTION 3 — DETAILED FINDINGS", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.3*cm))

    if not findings:
        story.append(Paragraph("No vulnerabilities were identified during this assessment.", styles["body"]))
        story.append(PageBreak())
        return story

    # Sort by severity before displaying
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "Info"))
    )

    for idx, finding in enumerate(sorted_findings, start=1):
        story.extend(_build_single_finding(idx, finding, styles))
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))

    story.append(PageBreak())
    return story


def _build_single_finding(idx, finding, styles):
    """
    Build flowables for a single vulnerability finding.

    Expected keys in finding dict:
        title, protocol, severity, owasp_id, cvss_score,
        cvss_justification, description, reproduction_steps,
        evidence_request, evidence_response, remediation
    """
    flowables = []

    title = finding.get("title", "Unnamed Finding")
    protocol = finding.get("protocol", "Unknown")
    severity = finding.get("severity", "Info")
    owasp_id = finding.get("owasp_id", "N/A")
    owasp_name = OWASP_NAMES.get(owasp_id, "Unknown")
    cvss = finding.get("cvss_score", "N/A")
    cvss_just = finding.get("cvss_justification", "")
    description = finding.get("description", "")
    steps = finding.get("reproduction_steps", [])
    req = finding.get("evidence_request", "")
    resp = finding.get("evidence_response", "")
    remediation = finding.get("remediation", "")

    # Finding header
    flowables.append(Paragraph(
        f"Finding {idx}: {title}", styles["finding_title"]
    ))

    # Metadata table
    meta_data = [
        ["Protocol", protocol, "Severity", severity],
        ["OWASP ID", owasp_id, "OWASP Category", owasp_name[:45]],
        ["CVSS Score", str(cvss), "CVSS Justification", cvss_just[:60]],
    ]
    meta_table = Table(meta_data, colWidths=[3*cm, 3*cm, 4*cm, 6*cm])
    meta_style = TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ECEFF1")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#ECEFF1")),
    ])
    # Colour severity cell
    sev_color = SEVERITY_COLORS.get(severity, colors.black)
    meta_style.add("TEXTCOLOR", (1, 0), (1, 0), sev_color)
    meta_style.add("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold")
    meta_table.setStyle(meta_style)
    flowables.append(meta_table)
    flowables.append(Spacer(1, 0.3*cm))

    # Description
    flowables.append(Paragraph("Description", styles["label"]))
    flowables.append(Paragraph(description, styles["body"]))
    flowables.append(Spacer(1, 0.2*cm))

    # Reproduction steps
    if steps:
        flowables.append(Paragraph("Reproduction Steps", styles["label"]))
        for i, step in enumerate(steps, 1):
            flowables.append(Paragraph(f"{i}. {step}", styles["body"]))
        flowables.append(Spacer(1, 0.2*cm))

    # Evidence — label format by protocol
    evidence_label = {
        "REST":    "HTTP Request / Response",
        "SOAP":    "SOAP Envelope / Response",
        "GraphQL": "GraphQL Query / Response",
    }.get(protocol, "Request / Response")

    if req:
        flowables.append(Paragraph(f"Evidence — {evidence_label} (Request)", styles["label"]))
        flowables.append(Preformatted(req[:1200], styles["code"]))
        flowables.append(Spacer(1, 0.1*cm))

    if resp:
        flowables.append(Paragraph(f"Evidence — {evidence_label} (Response)", styles["label"]))
        flowables.append(Preformatted(resp[:1200], styles["code"]))
        flowables.append(Spacer(1, 0.2*cm))

    # Remediation
    flowables.append(Paragraph("Remediation", styles["label"]))
    flowables.append(Paragraph(remediation, styles["body"]))

    return flowables


# ─────────────────────────────────────────────────────────────
# SECTION 4 — REMEDIATION SUMMARY TABLE
# ─────────────────────────────────────────────────────────────

def build_remediation_table(findings, styles):
    """
    Build a ranked summary table of all findings with fix priority.
    Audience: management and engineering leads.
    """
    story = []

    story.append(Paragraph("SECTION 4 — REMEDIATION SUMMARY TABLE", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.3*cm))

    effort_map = {
        "Critical": "Immediate (< 24h)",
        "High":     "Short-term (< 1 week)",
        "Medium":   "Medium-term (< 1 month)",
        "Low":      "Backlog (next quarter)",
        "Info":     "Optional",
    }

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "Info"))
    )

    table_data = [["#", "Finding", "Protocol", "Severity", "OWASP", "Fix Effort", "Priority"]]
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "Info")
        table_data.append([
            str(i),
            f.get("title", "Unknown")[:35],
            f.get("protocol", "—"),
            sev,
            f.get("owasp_id", "—"),
            effort_map.get(sev, "TBD"),
            "P1" if sev == "Critical" else
            "P2" if sev == "High" else
            "P3" if sev == "Medium" else "P4",
        ])

    col_widths = [1*cm, 5.5*cm, 2*cm, 2*cm, 1.5*cm, 4*cm, 1.5*cm]
    rem_table = Table(table_data, colWidths=col_widths)
    rem_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (3, 0), (3, -1), "CENTER"),
        ("ALIGN", (4, 0), (4, -1), "CENTER"),
        ("ALIGN", (6, 0), (6, -1), "CENTER"),
    ])
    # Colour severity cells
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "Info")
        rem_style.add("TEXTCOLOR", (3, i), (3, i), SEVERITY_COLORS.get(sev, colors.black))
        rem_style.add("FONTNAME", (3, i), (3, i), "Helvetica-Bold")

    rem_table.setStyle(rem_style)
    story.append(rem_table)
    story.append(PageBreak())
    return story


# ─────────────────────────────────────────────────────────────
# SECTION 5 — APPENDIX
# ─────────────────────────────────────────────────────────────

def build_appendix(raw_logs, tool_config, styles):
    """
    Build the appendix with raw request/response logs,
    tool configuration, and OWASP reference links.

    Args:
        raw_logs: list of strings (raw log lines from audit CSV or scan output)
        tool_config: dict of CLI arguments used during this scan
    """
    story = []

    story.append(Paragraph("SECTION 5 — APPENDIX", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.3*cm))

    # Tool configuration used
    story.append(Paragraph("A — Tool Configuration", styles["subsection_header"]))
    if tool_config:
        config_lines = "\n".join(f"  {k}: {v}" for k, v in tool_config.items())
        story.append(Preformatted(config_lines, styles["code"]))
    else:
        story.append(Paragraph("No configuration recorded.", styles["body"]))
    story.append(Spacer(1, 0.3*cm))

    # Raw logs (truncated to avoid bloating PDF)
    story.append(Paragraph("B — Raw Audit Log (last 50 entries)", styles["subsection_header"]))
    if raw_logs:
        log_text = "\n".join(raw_logs[-50:])
        story.append(Preformatted(log_text[:3000], styles["code"]))
    else:
        story.append(Paragraph("No audit log entries available.", styles["body"]))
    story.append(Spacer(1, 0.3*cm))

    # OWASP references
    story.append(Paragraph("C — References", styles["subsection_header"]))
    references = [
        "OWASP API Security Top 10 (2023): https://owasp.org/API-Security/",
        "CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1",
        "crAPI Vulnerable REST Lab: https://github.com/OWASP/crAPI",
        "DVGA Vulnerable GraphQL Lab: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
        "WebGoat SOAP Lab: https://github.com/WebGoat/WebGoat",
        "JWT Security Best Practices: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html",
        "XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ]
    for ref in references:
        story.append(Paragraph(f"• {ref}", styles["body"]))

    return story


# ─────────────────────────────────────────────────────────────
# COVER PAGE
# ─────────────────────────────────────────────────────────────

def build_cover_page(target_urls, scan_date, styles):
    """
    Build the report cover page with title, target, and date.
    """
    story = []
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("AEGIS-API", styles["title"]))
    story.append(Paragraph("Unified API Security Assessment Report", styles["subtitle"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"Assessment Date: {scan_date}", styles["body"]))
    story.append(Paragraph(f"Protocols Tested: {', '.join(target_urls.keys())}", styles["body"]))
    for proto, url in target_urls.items():
        story.append(Paragraph(f"  {proto}: {url}", styles["body"]))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "CONFIDENTIAL — For authorized recipient only. "
        "Do not distribute without permission.",
        ParagraphStyle("Warn", parent=styles["body"], textColor=colors.red, fontSize=9)
    ))
    story.append(PageBreak())
    return story


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def generate_report(findings, target_urls, tool_config=None, raw_logs=None, output_dir="reports"):
    """
    Generate the complete unified VAPT PDF report.

    Args:
        findings:     list of finding dicts from all scanner modules
        target_urls:  dict mapping protocol label to target URL
                      e.g. {"REST": "http://localhost:8888", "GraphQL": "http://localhost:5013/graphql"}
        tool_config:  dict of CLI arguments used (for appendix)
        raw_logs:     list of raw log strings (for appendix)
        output_dir:   directory to write the PDF into

    Returns:
        str: path to generated PDF file
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"aegis_report_{timestamp}.pdf")

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title="Aegis-API Security Assessment Report",
        author="Aegis-API Scanner",
    )

    styles = _build_styles()
    story = []

    story.extend(build_cover_page(target_urls, scan_date, styles))
    story.extend(build_executive_summary(findings, target_urls, styles))
    story.extend(build_scope_and_methodology(target_urls, scan_date, styles))
    story.extend(build_detailed_findings(findings, styles))
    story.extend(build_remediation_table(findings, styles))
    story.extend(build_appendix(raw_logs or [], tool_config or {}, styles))

    doc.build(story)
    print(f"[+] Report generated: {output_path}")
    return output_path
