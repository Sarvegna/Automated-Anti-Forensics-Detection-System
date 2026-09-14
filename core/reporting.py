import json
import os
from datetime import datetime


def generate_json_report(pipeline_result, case_info=None, output_path=None):
    """
    Generates a structured JSON forensic investigation report.
    """
    if case_info is None:
        case_info = {}

    report_data = {
        "report_metadata": {
            "title": "Automated Anti-Forensics Detection System Report",
            "generated_at": datetime.now().isoformat(),
            "case_id": case_info.get("case_id", "CASE-UNKNOWN"),
            "evidence_id": case_info.get("evidence_id", "EVID-UNKNOWN"),
            "analyst": case_info.get("analyst", "Investigator")
        },
        "evidence_summary": {
            "evidence_reference": pipeline_result.get("evidence_reference"),
            "file_path": pipeline_result.get("file_path"),
            "source_type": pipeline_result.get("source_type"),
            "evidence_context": pipeline_result.get("evidence_context", {}),
            "sha256": pipeline_result.get("sha256"),
            "identified_artifact": pipeline_result.get("identification", {}).get("evidence_type", "Unknown")
        },
        "execution_summary": {
            "applicable_modules": pipeline_result.get("applicable_modules", []),
            "module_statuses": pipeline_result.get("module_statuses", {})
        },
        "risk_assessment": pipeline_result.get("risk_result", {}),
        "findings": pipeline_result.get("findings", []),
        "module_results": pipeline_result.get("module_results", {})
    }

    json_str = json.dumps(report_data, indent=2, default=str)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str


def generate_html_report(pipeline_result, case_info=None, output_path=None):
    """
    Generates a standalone, styled HTML forensic investigation report.
    """
    if case_info is None:
        case_info = {}

    case_id = case_info.get("case_id", "CASE-UNKNOWN")
    evidence_id = case_info.get("evidence_id", "EVID-UNKNOWN")
    analyst = case_info.get("analyst", "Investigator")
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    evidence_ref = pipeline_result.get("evidence_reference", "N/A")
    sha256 = pipeline_result.get("sha256", "N/A")
    artifact_type = pipeline_result.get("identification", {}).get("evidence_type", "Unknown")

    risk_result = pipeline_result.get("risk_result", {})
    risk_score = risk_result.get("score", 0)
    risk_level = risk_result.get("risk_level", "LOW")

    findings = pipeline_result.get("findings", [])
    module_statuses = pipeline_result.get("module_statuses", {})

    status_badge_colors = {
        "SUCCESS": "#3ddc97",
        "NOT_APPLICABLE": "#8b90a0",
        "UNSUPPORTED": "#f39c12",
        "MISSING_DEPENDENCY": "#e67e22",
        "FAILED": "#ff6b5c"
    }

    risk_color = "#3ddc97" if risk_level == "LOW" else ("#5cd6f5" if risk_level == "MEDIUM" else "#ff6b5c")

    # Render module status table rows
    status_rows_html = ""
    for mod, st_val in module_statuses.items():
        color = status_badge_colors.get(st_val, "#ffffff")
        status_rows_html += f"""
        <tr>
            <td style="padding:10px; border-bottom:1px solid #2a2e3a;">{mod}</td>
            <td style="padding:10px; border-bottom:1px solid #2a2e3a;">
                <span style="background:{color}22; color:{color}; border:1px solid {color}; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{st_val}</span>
            </td>
        </tr>
        """

    # Render findings table rows
    findings_rows_html = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "LOW")
            sev_color = "#ff6b5c" if sev == "HIGH" else ("#f39c12" if sev == "MEDIUM" else "#3ddc97")
            findings_rows_html += f"""
            <tr>
                <td style="padding:10px; border-bottom:1px solid #2a2e3a; font-family:monospace;">{f.get('finding_id')}</td>
                <td style="padding:10px; border-bottom:1px solid #2a2e3a;">{f.get('type')}</td>
                <td style="padding:10px; border-bottom:1px solid #2a2e3a;">
                    <span style="color:{sev_color}; font-weight:bold;">{sev}</span>
                </td>
                <td style="padding:10px; border-bottom:1px solid #2a2e3a;">{f.get('reason')}</td>
                <td style="padding:10px; border-bottom:1px solid #2a2e3a;">{f.get('source')}</td>
            </tr>
            """
    else:
        findings_rows_html = """
        <tr>
            <td colspan="5" style="padding:16px; text-align:center; color:#8b90a0;">No anti-forensic indicators detected during automated analysis.</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Report — {case_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #12141a; color: #e1e4ea; margin: 0; padding: 30px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1a1d24; border: 1px solid #2a2e3a; border-radius: 8px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .header {{ border-bottom: 2px solid #5cd6f5; padding-bottom: 15px; margin-bottom: 25px; }}
        .header h1 {{ color: #ffffff; margin: 0 0 5px 0; font-size: 28px; }}
        .header .subtitle {{ color: #8b90a0; font-size: 14px; font-family: monospace; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 25px; }}
        .card {{ background: #222632; border: 1px solid #2a2e3a; border-radius: 6px; padding: 15px; }}
        .card-label {{ font-size: 12px; color: #8b90a0; font-family: monospace; margin-bottom: 5px; }}
        .card-value {{ font-size: 16px; color: #ffffff; font-weight: 600; word-break: break-all; }}
        .risk-banner {{ background: linear-gradient(145deg, #1e222c, #191c24); border: 2px solid {risk_color}; border-radius: 8px; padding: 20px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }}
        .risk-title {{ font-size: 14px; color: #8b90a0; font-family: monospace; }}
        .risk-score {{ font-size: 36px; font-weight: bold; color: #ffffff; font-family: monospace; }}
        .risk-level {{ font-size: 28px; font-weight: bold; color: {risk_color}; letter-spacing: 2px; }}
        h2 {{ color: #f2f3f5; font-size: 18px; border-left: 4px solid #5cd6f5; padding-left: 10px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; background: #222632; border-radius: 6px; overflow: hidden; }}
        th {{ background: #2a2e3a; color: #8b90a0; text-align: left; padding: 10px; font-size: 12px; font-family: monospace; }}
        .footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #2a2e3a; font-size: 12px; color: #6b7080; font-family: monospace; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Automated Anti-Forensics Detection System</h1>
            <div class="subtitle">OFFICIAL FORENSIC EXAMINATION REPORT · GENERATED {gen_time}</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-label">CASE ID</div>
                <div class="card-value">{case_id}</div>
            </div>
            <div class="card">
                <div class="card-label">EVIDENCE ID</div>
                <div class="card-value">{evidence_id}</div>
            </div>
            <div class="card">
                <div class="card-label">ANALYST</div>
                <div class="card-value">{analyst}</div>
            </div>
            <div class="card">
                <div class="card-label">EVIDENCE FILE</div>
                <div class="card-value">{evidence_ref}</div>
            </div>
            <div class="card">
                <div class="card-label">IDENTIFIED ARTIFACT</div>
                <div class="card-value">{artifact_type}</div>
            </div>
            <div class="card">
                <div class="card-label">SHA-256 INTEGRITY</div>
                <div class="card-value" style="font-size:11px; font-family:monospace;">{sha256}</div>
            </div>
        </div>

        <div class="risk-banner">
            <div>
                <div class="risk-title">OVERALL RISK SCORE</div>
                <div class="risk-score">{risk_score} / 100</div>
            </div>
            <div class="risk-level">{risk_level}</div>
        </div>

        <h2>ANALYSIS MODULE EXECUTIONS</h2>
        <table>
            <thead>
                <tr>
                    <th>MODULE NAME</th>
                    <th>EXECUTION STATUS</th>
                </tr>
            </thead>
            <tbody>
                {status_rows_html}
            </tbody>
        </table>

        <h2>STRUCTURED FINDINGS</h2>
        <table>
            <thead>
                <tr>
                    <th>FINDING ID</th>
                    <th>TYPE</th>
                    <th>SEVERITY</th>
                    <th>REASON / OBSERVATION</th>
                    <th>SOURCE</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows_html}
            </tbody>
        </table>

        <div class="footer">
            CONFIDENTIAL FORENSIC REPORT · AUTOMATED ANTI-FORENSICS DETECTION SYSTEM MVP
        </div>
    </div>
</body>
</html>
"""

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    return html_content
