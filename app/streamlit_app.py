import streamlit as st
import sys
import os
import tempfile
import uuid
from datetime import datetime
import pandas as pd
import altair as alt

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis
from core.reporting import generate_json_report, generate_html_report
from core.risk_scoring import INDICATOR_WEIGHTS
from core.findings import severity_from_points
from core.storage import (
    save_investigation_history,
    get_investigation_history,
    get_investigation_by_id,
    add_audit_log_entry,
    get_audit_logs
)

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Automated Anti-Forensics Detection System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# DESIGN SYSTEM: TYPOGRAPHY (IBM Plex Sans & Mono) + DARK CHARCOAL STYLING
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;0,700;1,400&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap');

    /* Global Dark Charcoal Surface & Standard IBM Plex Sans Typography */
    html, body, [class*="css"], .stApp {
        background-color: #0f131d !important;
        color: #f1f5f9 !important;
        font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 17px !important;
        line-height: 1.5 !important;
    }

    /* Sidebar Dark Slate Styling */
    section[data-testid="stSidebar"] {
        background-color: #161b26 !important;
        border-right: 1px solid #252d3d !important;
    }
    section[data-testid="stSidebar"] [class*="css"] {
        color: #f1f5f9 !important;
    }
    section[data-testid="stSidebar"] label {
        color: #e2e8f0 !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 16px !important;
        font-weight: 600 !important;
    }

    /* Technical Elements Monospace Class */
    .tech-mono, .finding-id, code, pre, .stCodeBlock {
        font-family: 'IBM Plex Mono', monospace !important;
    }

    /* Titles and Headings Hierarchy */
    .main-title {
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 34px !important;
        font-weight: 700 !important;
        color: #ffffff !important;
        letter-spacing: 0.5px !important;
        margin-bottom: 24px !important;
        text-transform: uppercase !important;
        border-bottom: 2px solid #252d3d !important;
        padding-bottom: 14px !important;
    }

    .page-heading {
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 25px !important;
        font-weight: 700 !important;
        color: #ffffff !important;
        margin-top: 6px !important;
        margin-bottom: 20px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    .section-heading {
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 22px !important;
        font-weight: 600 !important;
        color: #ffffff !important;
        margin-top: 24px !important;
        margin-bottom: 14px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
        border-left: 4px solid #3b82f6 !important;
        padding-left: 12px !important;
    }

    /* Charcoal Panel Cards */
    .dark-panel {
        background-color: #1a2130 !important;
        border: 1px solid #2b354d !important;
        border-radius: 8px !important;
        padding: 20px !important;
        margin-bottom: 20px !important;
        font-size: 17px !important;
    }

    /* Metrics Styling */
    div[data-testid="stMetric"] {
        background-color: #1a2130 !important;
        border: 1px solid #2b354d !important;
        border-radius: 8px !important;
        padding: 16px 20px !important;
    }
    div[data-testid="stMetric"] label {
        color: #94a3b8 !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 15px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
    }
    div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 26px !important;
        font-weight: 700 !important;
    }

    /* Custom Tables */
    .forensic-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
        margin-bottom: 20px;
        background-color: #1a2130;
        border: 1px solid #2b354d;
        border-radius: 8px;
        overflow: hidden;
    }
    .forensic-table th {
        background-color: #222c40;
        color: #cbd5e1;
        font-family: 'IBM Plex Sans', sans-serif;
        font-size: 16px;
        font-weight: 600;
        text-align: left;
        padding: 14px 16px;
        border-bottom: 1px solid #2b354d;
    }
    .forensic-table td {
        color: #f1f5f9;
        font-family: 'IBM Plex Sans', sans-serif;
        font-size: 16px;
        padding: 12px 16px;
        border-bottom: 1px solid #252d3d;
    }
    .forensic-table tr:hover {
        background-color: #222a3d;
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
    }
    .badge-success { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid #22c55e; }
    .badge-low { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid #22c55e; }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid #eab308; }
    .badge-unsupported { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid #eab308; }
    .badge-high { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; }
    .badge-failed { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; }
    .badge-na { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid #64748b; }

    /* Risk Score Banner */
    .risk-banner {
        background-color: #1a2130;
        border: 1px solid #2b354d;
        border-radius: 8px;
        padding: 22px 28px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 24px;
    }
    .risk-banner.low { border-left: 6px solid #22c55e; }
    .risk-banner.medium { border-left: 6px solid #eab308; }
    .risk-banner.high { border-left: 6px solid #ef4444; }

    /* Workflow Stepper */
    .workflow-box {
        background-color: #1a2130;
        border: 1px solid #2b354d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 20px;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 15px;
        color: #60a5fa;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
if "case_id" not in st.session_state:
    st.session_state.case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
if "evidence_id" not in st.session_state:
    st.session_state.evidence_id = f"EVID-{str(uuid.uuid4())[:8].upper()}"
if "investigator_name" not in st.session_state:
    st.session_state.investigator_name = ""
if "pipeline_result" not in st.session_state:
    st.session_state.pipeline_result = None
if "evidence_meta" not in st.session_state:
    st.session_state.evidence_meta = None
if "selected_module" not in st.session_state:
    st.session_state.selected_module = None
if "active_nav_page" not in st.session_state:
    st.session_state.active_nav_page = "Investigation"

STATUS_COLORS = {
    "SUCCESS": "#22c55e",
    "NOT_APPLICABLE": "#64748b",
    "UNSUPPORTED": "#eab308",
    "MISSING_DEPENDENCY": "#eab308",
    "FAILED": "#ef4444",
    "CORRUPTED": "#ef4444"
}

# Header Banner
st.markdown('<div class="main-title">AUTOMATED ANTI-FORENSICS DETECTION SYSTEM</div>', unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SIDEBAR NAVIGATION & DETECTED MODULES
# -----------------------------------------------------------------------------
st.sidebar.markdown("<div style='font-size:16px; font-weight:700; color:#ffffff; margin-bottom:8px;'>NAVIGATION</div>", unsafe_allow_html=True)

nav_options = ["Investigation", "Analysis Overview", "Module Results", "Findings Table", "Investigation History", "Audit Log", "Reports & Export", "Help"]
selected_page = st.sidebar.radio(
    "Navigation Options",
    nav_options,
    index=nav_options.index(st.session_state.active_nav_page) if st.session_state.active_nav_page in nav_options else 0,
    label_visibility="collapsed"
)
st.session_state.active_nav_page = selected_page

st.sidebar.markdown("---")

# Active Evidence Box in Sidebar
st.sidebar.markdown("<div style='font-size:16px; font-weight:700; color:#ffffff; margin-bottom:8px;'>CURRENT EVIDENCE</div>", unsafe_allow_html=True)

if st.session_state.pipeline_result is not None and st.session_state.evidence_meta is not None:
    meta = st.session_state.evidence_meta
    result = st.session_state.pipeline_result
    st.sidebar.markdown(f"**Investigator:** `{st.session_state.investigator_name}`")
    st.sidebar.markdown(f"**Case ID:** <span class='tech-mono' style='color:#60a5fa;'>{st.session_state.case_id}</span>", unsafe_allow_html=True)
    st.sidebar.markdown(f"**Evidence ID:** <span class='tech-mono' style='color:#60a5fa;'>{st.session_state.evidence_id}</span>", unsafe_allow_html=True)
    st.sidebar.markdown(f"**File:** `{meta.get('filename')}`")
    st.sidebar.markdown(f"**Type:** `{result['identification']['evidence_type']}`")
    
    r_score = result.get("risk_result", {}).get("score", 0)
    r_level = result.get("risk_result", {}).get("risk_level", "LOW")
    r_color = "#22c55e" if r_level == "LOW" else ("#eab308" if r_level == "MEDIUM" else "#ef4444")
    st.sidebar.markdown(f"**Risk Score:** <span style='color:{r_color}; font-weight:700;'>{r_score}/100 ({r_level})</span>", unsafe_allow_html=True)
else:
    st.sidebar.markdown("Status: **No Evidence Loaded**")
    st.sidebar.markdown("Investigator: " + (f"`{st.session_state.investigator_name}`" if st.session_state.investigator_name else "*Not set*"))

st.sidebar.markdown("---")

# DETECTED MODULES SECTION IN SIDEBAR
st.sidebar.markdown("<div style='font-size:16px; font-weight:700; color:#ffffff; margin-bottom:8px;'>DETECTED MODULES</div>", unsafe_allow_html=True)

if st.session_state.pipeline_result is not None:
    statuses = st.session_state.pipeline_result.get("module_statuses", {})
    all_modules = [
        "Timestamp Analysis",
        "Hidden File Check",
        "YARA Analysis",
        "Browser Artifact Analysis",
        "Event Log Analysis",
        "Memory Analysis (Volatility 3)",
        "NTFS Artifact Analysis"
    ]
    for mod in all_modules:
        m_status = statuses.get(mod, "NOT_APPLICABLE")
        badge_cls = "badge-success" if m_status == "SUCCESS" else (
            "badge-medium" if m_status in ["UNSUPPORTED", "MISSING_DEPENDENCY"] else (
                "badge-failed" if m_status in ["FAILED", "CORRUPTED"] else "badge-na"
            )
        )
        col_m1, col_m2 = st.sidebar.columns([3, 2])
        with col_m1:
            if st.button(f"{mod}", key=f"side_mod_{mod}"):
                st.session_state.selected_module = mod
                st.session_state.active_nav_page = "Module Results"
                st.rerun()
        with col_m2:
            st.markdown(f"<span class='badge {badge_cls}'>{m_status}</span>", unsafe_allow_html=True)
else:
    st.sidebar.markdown("<span style='color:#64748b; font-size:15px;'>Upload evidence to run automated detection pipeline.</span>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# PAGE 1: INVESTIGATION (ENFORCED INVESTIGATOR SETUP WORKFLOW)
# -----------------------------------------------------------------------------
if selected_page == "Investigation":
    st.markdown('<div class="page-heading">INVESTIGATION SETUP & EVIDENCE UPLOAD</div>', unsafe_allow_html=True)

    st.markdown('<div class="workflow-box">WORKFLOW ENFORCEMENT: INVESTIGATOR NAME &rarr; CASE DETAILS &rarr; EVIDENCE UPLOAD</div>', unsafe_allow_html=True)

    # 1. Investigator Name Input (REQUIRED FIRST FIELD)
    st.markdown('<div class="section-heading">1. Investigator Information</div>', unsafe_allow_html=True)
    
    investigator_input = st.text_input(
        "Investigator Name (Required to enable Evidence Upload)",
        value=st.session_state.investigator_name,
        placeholder="Enter full investigator name (e.g., Det. J. Miller)"
    )

    if investigator_input != st.session_state.investigator_name:
        st.session_state.investigator_name = investigator_input
        if investigator_input.strip():
            add_audit_log_entry(
                action="Investigator Set",
                case_id=st.session_state.case_id,
                evidence_id=st.session_state.evidence_id,
                investigator=investigator_input,
                details="Investigator identity registered for session."
            )

    is_investigator_provided = bool(st.session_state.investigator_name.strip())

    if not is_investigator_provided:
        st.warning("⚠️ **INVESTIGATOR NAME REQUIRED**: Please enter the Investigator Name above. Evidence Upload controls remain locked until Investigator Name is provided.")

    # 2. Case Details
    st.markdown('<div class="section-heading">2. Case & Evidence Identifiers</div>', unsafe_allow_html=True)
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        st.session_state.case_id = st.text_input("Case ID", value=st.session_state.case_id, disabled=not is_investigator_provided)
    with col_c2:
        st.session_state.evidence_id = st.text_input("Evidence ID", value=st.session_state.evidence_id, disabled=not is_investigator_provided)

    # 3. Evidence Input Method
    st.markdown('<div class="section-heading">3. Upload Digital Evidence File</div>', unsafe_allow_html=True)
    input_method_choice = None
    if is_investigator_provided:
        input_method_choice = st.radio(
            "Evidence Input Method",
            ["Upload Evidence File", "Local Evidence Path"],
            key="evidence_input_method_radio"
        )
    else:
        st.info("🔒 Evidence Input is disabled. Enter the Investigator Name above to unlock input options.")

    if input_method_choice == "Upload Evidence File":
        with st.container():
            uploaded_file = st.file_uploader(
                "Upload Evidence File",
                key="investigation_file_uploader",
                help="Select or drag and drop a digital evidence file for automated analysis."
            )

            if uploaded_file is not None:
                current_fn = st.session_state.evidence_meta.get("filename") if st.session_state.evidence_meta else None
                if current_fn != uploaded_file.name:
                    file_bytes = uploaded_file.getvalue()
                    file_ext = os.path.splitext(uploaded_file.name)[1]

                    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
                        tmp.write(file_bytes)
                        temp_path = tmp.name

                    source_metadata = {
                        "input_method": "browser_upload",
                        "is_web_upload": True,
                        "filename": uploaded_file.name,
                        "size": len(file_bytes)
                    }

                    if hasattr(uploaded_file, "last_modified") and uploaded_file.last_modified:
                        try:
                            source_metadata["last_modified"] = datetime.fromtimestamp(uploaded_file.last_modified / 1000.0, tz=timezone.utc)
                        except Exception:
                            pass

                    try:
                        with st.spinner("Executing automated evidence pipeline..."):
                            add_audit_log_entry(
                                action="Evidence Uploaded",
                                case_id=st.session_state.case_id,
                                evidence_id=st.session_state.evidence_id,
                                investigator=st.session_state.investigator_name,
                                details=f"Uploaded {uploaded_file.name} ({len(file_bytes)} bytes) via Browser Upload"
                            )

                            pipeline_result = run_automated_analysis(
                                temp_path,
                                evidence_reference=uploaded_file.name,
                                source_metadata=source_metadata
                            )

                            analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

                            ident = pipeline_result.get("identification", {})
                            evidence_meta = {
                                "filename": uploaded_file.name,
                                "size": len(file_bytes),
                                "extension": file_ext if file_ext else "(none)",
                                "analysis_timestamp": analysis_time,
                                "confidence": ident.get("confidence", "UNKNOWN"),
                                "detected_format": ident.get("detected_format", "Unknown"),
                                "detection_method": ident.get("detection_method", "N/A"),
                                "reason": ident.get("reason", "N/A"),
                                "routed_module": ident.get("routed_module", "General Analysis only")
                            }

                            st.session_state.pipeline_result = pipeline_result
                            st.session_state.evidence_meta = evidence_meta

                            # Record Audit Log Entries
                            add_audit_log_entry(
                                action="SHA-256 Calculated",
                                case_id=st.session_state.case_id,
                                evidence_id=st.session_state.evidence_id,
                                investigator=st.session_state.investigator_name,
                                details=f"SHA-256: {pipeline_result.get('sha256')}"
                            )
                            add_audit_log_entry(
                                action="Evidence Identified",
                                case_id=st.session_state.case_id,
                                evidence_id=st.session_state.evidence_id,
                                investigator=st.session_state.investigator_name,
                                details=f"Type: {ident.get('evidence_type')} (Confidence: {ident.get('confidence')})"
                            )
                            add_audit_log_entry(
                                action="Risk Calculated",
                                case_id=st.session_state.case_id,
                                evidence_id=st.session_state.evidence_id,
                                investigator=st.session_state.investigator_name,
                                details=f"Score: {pipeline_result['risk_result']['score']}/100 ({pipeline_result['risk_result']['risk_level']})"
                            )

                            # Save to Persistent Investigation History
                            save_investigation_history(
                                case_id=st.session_state.case_id,
                                evidence_id=st.session_state.evidence_id,
                                investigator=st.session_state.investigator_name,
                                filename=uploaded_file.name,
                                artifact_type=ident.get('evidence_type', 'Unknown'),
                                risk_score=pipeline_result['risk_result']['score'],
                                risk_level=pipeline_result['risk_result']['risk_level'],
                                status=pipeline_result.get("status", "SUCCESS"),
                                pipeline_result=pipeline_result,
                                evidence_meta=evidence_meta
                            )

                            st.success(f"✅ Evidence processing complete for {uploaded_file.name}! Results saved to investigation history.")
                    finally:
                        if os.path.exists(temp_path):
                            try:
                                os.unlink(temp_path)
                            except Exception:
                                pass

    if input_method_choice == "Local Evidence Path":
        with st.container():
            local_path_val = st.text_input(
                "Evidence File Path",
                placeholder="e.g. evidence/input/anomaly_test.txt",
                key="local_evidence_file_path_input"
            )

            if st.button("Analyze Local Evidence File", key="btn_analyze_local_path"):
                target_path = local_path_val.strip()
                if not target_path or not os.path.exists(target_path) or not os.path.isfile(target_path):
                    st.error("File not found or invalid evidence path.")
                else:
                    file_size = os.path.getsize(target_path)
                    file_name = os.path.basename(target_path)
                    file_ext = os.path.splitext(file_name)[1]

                    source_metadata = {
                        "input_method": "local_path",
                        "is_web_upload": False,
                        "filename": file_name,
                        "size": file_size
                    }

                    with st.spinner("Executing automated evidence pipeline on local path..."):
                        add_audit_log_entry(
                            action="Local Evidence Path Analyzed",
                            case_id=st.session_state.case_id,
                            evidence_id=st.session_state.evidence_id,
                            investigator=st.session_state.investigator_name,
                            details=f"Analyzed local path: {target_path}"
                        )

                        pipeline_result = run_automated_analysis(
                            target_path,
                            evidence_reference=file_name,
                            source_metadata=source_metadata
                        )

                        analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
                        ident = pipeline_result.get("identification", {})
                        evidence_meta = {
                            "filename": file_name,
                            "size": file_size,
                            "extension": file_ext if file_ext else "(none)",
                            "analysis_timestamp": analysis_time,
                            "confidence": ident.get("confidence", "UNKNOWN"),
                            "detected_format": ident.get("detected_format", "Unknown"),
                            "detection_method": ident.get("detection_method", "N/A"),
                            "reason": ident.get("reason", "N/A"),
                            "routed_module": ident.get("routed_module", "General Analysis only")
                        }

                        st.session_state.pipeline_result = pipeline_result
                        st.session_state.evidence_meta = evidence_meta

                        add_audit_log_entry(
                            action="SHA-256 Calculated",
                            case_id=st.session_state.case_id,
                            evidence_id=st.session_state.evidence_id,
                            investigator=st.session_state.investigator_name,
                            details=f"SHA-256: {pipeline_result.get('sha256')}"
                        )
                        add_audit_log_entry(
                            action="Evidence Identified",
                            case_id=st.session_state.case_id,
                            evidence_id=st.session_state.evidence_id,
                            investigator=st.session_state.investigator_name,
                            details=f"Type: {ident.get('evidence_type')} (Confidence: {ident.get('confidence')})"
                        )

                        save_investigation_history(
                            case_id=st.session_state.case_id,
                            evidence_id=st.session_state.evidence_id,
                            investigator=st.session_state.investigator_name,
                            filename=file_name,
                            artifact_type=ident.get('evidence_type', 'Unknown'),
                            risk_score=pipeline_result['risk_result']['score'],
                            risk_level=pipeline_result['risk_result']['risk_level'],
                            status=pipeline_result.get("status", "SUCCESS"),
                            pipeline_result=pipeline_result,
                            evidence_meta=evidence_meta
                        )

                        st.success(f"✅ Local evidence analysis complete for {file_name}!")

    # 4. Evidence Information Summary Card
    if st.session_state.pipeline_result is not None and st.session_state.evidence_meta is not None:
        result = st.session_state.pipeline_result
        meta = st.session_state.evidence_meta
        ident = result.get("identification", {})

        st.markdown('<div class="section-heading">4. Uploaded Evidence Metadata & Identification</div>', unsafe_allow_html=True)
        
        info_col1, info_col2, info_col3, info_col4 = st.columns(4)
        with info_col1:
            st.metric("Original Filename", meta["filename"])
        with info_col2:
            size_kb = meta["size"] / 1024
            size_str = f"{size_kb:.2f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"
            st.metric("File Size", size_str)
        with info_col3:
            st.metric("Artifact Type", ident.get("evidence_type", "Unknown"))
        with info_col4:
            conf_val = ident.get("confidence", "UNKNOWN")
            st.metric("Confidence", conf_val)

        conf_badge = "badge-success" if conf_val == "HIGH" else ("badge-medium" if conf_val == "MEDIUM" else "badge-failed")
        routed_mod = ident.get("routed_module", "General Analysis only")
        analysis_status = "SUPPORTED & ROUTED (" + routed_mod + ")" if ident.get("supports_specific_analysis") else "NOT YET IMPLEMENTED (General Analysis Only)"

        source_type_val = result.get("source_type") or result.get("evidence_context", {}).get("source_type", "individual_file")
        source_label = "Forensic Image" if source_type_val == "forensic_image" else "Individual Evidence File"
        input_method_val = result.get("evidence_context", {}).get("input_method") or result.get("input_method", "browser_upload")
        input_method_label = "Local Evidence Path" if input_method_val in ("local_path", "Local Evidence Path") else "Browser Upload"
        ts_prov_val = result.get("evidence_context", {}).get("timestamp_provenance") or result.get("timestamp_result", {}).get("timestamp_provenance", {}).get("category", "local_filesystem")

        st.markdown(f"""
        <div class="dark-panel">
            <table style="width:100%; color:#f1f5f9; font-size:16px; border-collapse:separate; border-spacing:0 8px;">
                <tr>
                    <td style="width:20%; font-weight:600; color:#cbd5e1;">Case ID:</td>
                    <td class="tech-mono" style="color:#60a5fa;">{st.session_state.case_id}</td>
                    <td style="width:20%; font-weight:600; color:#cbd5e1;">Evidence ID:</td>
                    <td class="tech-mono" style="color:#60a5fa;">{st.session_state.evidence_id}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Evidence Source:</td>
                    <td style="color:#60a5fa; font-weight:600;">{source_label}</td>
                    <td style="font-weight:600; color:#cbd5e1;">Input Method:</td>
                    <td style="color:#ffffff; font-weight:600;">{input_method_label}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Timestamp Provenance:</td>
                    <td class="tech-mono" style="color:#38bdf8; font-weight:600;">{ts_prov_val}</td>
                    <td style="font-weight:600; color:#cbd5e1;">Evidence Type:</td>
                    <td style="color:#38bdf8; font-weight:600;">{ident.get('evidence_type', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Evidence File Path:</td>
                    <td colspan="3" class="tech-mono" style="color:#ffffff; word-break:break-all;">{result.get('file_path')}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">SHA-256:</td>
                    <td colspan="3" class="tech-mono" style="color:#38bdf8; word-break:break-all;">{result['sha256']}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Extension:</td>
                    <td class="tech-mono" style="color:#ffffff;">{ident.get('extension', '(none)')}</td>
                    <td style="font-weight:600; color:#cbd5e1;">Detected File Format:</td>
                    <td style="color:#38bdf8; font-weight:600;">{ident.get('detected_format', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Detection Method:</td>
                    <td style="color:#ffffff;">{ident.get('detection_method', 'N/A')}</td>
                    <td style="font-weight:600; color:#cbd5e1;">Confidence:</td>
                    <td><span class="badge {conf_badge}">{conf_val}</span></td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Analysis Module:</td>
                    <td colspan="3" style="color:#eab308; font-weight:600;">{analysis_status}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Reason for ID:</td>
                    <td colspan="3" style="color:#cbd5e1; font-style:italic;">{ident.get('reason', 'N/A')}</td>
                </tr>
                <tr>
                    <td style="font-weight:600; color:#cbd5e1;">Investigator:</td>
                    <td style="color:#ffffff;">{st.session_state.investigator_name}</td>
                    <td style="font-weight:600; color:#cbd5e1;">Analysis Timestamp:</td>
                    <td class="tech-mono" style="color:#94a3b8;">{meta.get('analysis_timestamp', 'N/A')}</td>
                </tr>
            </table>
        </div>
        """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# PAGE 2: ANALYSIS OVERVIEW & VISUALIZATIONS
# -----------------------------------------------------------------------------
elif selected_page == "Analysis Overview":
    st.markdown('<div class="page-heading">MAIN ANALYSIS OVERVIEW & VISUALIZATIONS</div>', unsafe_allow_html=True)

    if st.session_state.pipeline_result is None:
        st.info("ℹ️ No evidence loaded. Please complete Investigator setup and upload evidence on the **Investigation** page.")
    else:
        result = st.session_state.pipeline_result
        risk_res = result.get("risk_result", {})
        score = risk_res.get("score", 0)
        level = risk_res.get("risk_level", "LOW")
        findings = result.get("findings", [])
        statuses = result.get("module_statuses", {})

        # 1. Overall Risk Score Card
        st.markdown('<div class="section-heading">1. Overall Risk Score</div>', unsafe_allow_html=True)
        level_class = level.lower()
        badge_cls = f"badge-{level_class}"
        
        st.markdown(f"""
        <div class="risk-banner {level_class}">
            <div>
                <div style="font-size:15px; font-weight:700; text-transform:uppercase; color:#94a3b8;">AGGREGATED ANTI-FORENSICS RISK</div>
                <div style="font-size:36px; font-weight:800; color:#ffffff; font-family:'IBM Plex Sans', sans-serif;">{score} / 100</div>
            </div>
            <div>
                <span class="badge {badge_cls}" style="font-size:22px; padding:8px 18px;">RISK LEVEL: {level}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 2. Forensic Visualizations Grid
        col_v1, col_v2 = st.columns(2)

        with col_v1:
            st.markdown('<div class="section-heading">2. Findings by Severity</div>', unsafe_allow_html=True)
            high_cnt = sum(1 for f in findings if f.get("severity") == "HIGH")
            med_cnt = sum(1 for f in findings if f.get("severity") == "MEDIUM")
            low_cnt = sum(1 for f in findings if f.get("severity") == "LOW")

            df_sev = pd.DataFrame([
                {"Severity": "HIGH", "Count": high_cnt, "Color": "#ef4444"},
                {"Severity": "MEDIUM", "Count": med_cnt, "Color": "#eab308"},
                {"Severity": "LOW", "Count": low_cnt, "Color": "#22c55e"}
            ])

            chart_sev = alt.Chart(df_sev).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X('Severity:N', title='Finding Severity', sort=['HIGH', 'MEDIUM', 'LOW'],
                        axis=alt.Axis(labelColor='#f1f5f9', titleColor='#cbd5e1', labelFontSize=14, titleFontSize=15)),
                y=alt.Y('Count:Q', title='Number of Findings',
                        axis=alt.Axis(labelColor='#f1f5f9', titleColor='#cbd5e1', labelFontSize=14, titleFontSize=15, tickMinStep=1)),
                color=alt.Color('Severity:N', scale=alt.Scale(domain=['HIGH', 'MEDIUM', 'LOW'], range=['#ef4444', '#eab308', '#22c55e']), legend=None),
                tooltip=['Severity', 'Count']
            ).properties(height=260).configure_view(strokeWidth=0)
            
            st.altair_chart(chart_sev, use_container_width=True)

        with col_v2:
            st.markdown('<div class="section-heading">3. Module Execution Summary</div>', unsafe_allow_html=True)
            status_counts = {}
            for st_val in statuses.values():
                status_counts[st_val] = status_counts.get(st_val, 0) + 1

            df_mod = pd.DataFrame([
                {"Status": k, "Count": v} for k, v in status_counts.items()
            ])

            color_map = {
                "SUCCESS": "#22c55e",
                "NOT_APPLICABLE": "#64748b",
                "UNSUPPORTED": "#eab308",
                "MISSING_DEPENDENCY": "#eab308",
                "FAILED": "#ef4444",
                "CORRUPTED": "#ef4444"
            }

            chart_mod = alt.Chart(df_mod).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X('Count:Q', title='Modules Count',
                        axis=alt.Axis(labelColor='#f1f5f9', titleColor='#cbd5e1', labelFontSize=14, titleFontSize=15, tickMinStep=1)),
                y=alt.Y('Status:N', title='Execution Status', sort='-x',
                        axis=alt.Axis(labelColor='#f1f5f9', titleColor='#cbd5e1', labelFontSize=14, titleFontSize=15)),
                color=alt.Color('Status:N', scale=alt.Scale(domain=list(color_map.keys()), range=list(color_map.values())), legend=None),
                tooltip=['Status', 'Count']
            ).properties(height=260).configure_view(strokeWidth=0)

            st.altair_chart(chart_mod, use_container_width=True)

        # 4. Forensic Timeline & Gap Visualization
        st.markdown('<div class="section-heading">4. Timeline & Activity Anomaly Visualization</div>', unsafe_allow_html=True)

        timeline_points = []
        # Extract actual file-system evidence timestamps from timestamp analysis
        ts_res = result.get("timestamp_result")
        if ts_res and isinstance(ts_res, dict):
            indicators = ts_res.get("indicators", [])

            def format_evidence_ts(dt_obj):
                if dt_obj is None:
                    return "Unavailable"
                if hasattr(dt_obj, "strftime"):
                    try:
                        return dt_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        return str(dt_obj)
                return str(dt_obj) if dt_obj else "Unavailable"

            # Event 1: File System Created
            created_dt = ts_res.get("created")
            created_str = format_evidence_ts(created_dt)
            created_anomaly = "Yes" if any(
                ind.get("type") == "Future Timestamp" and "Created" in ind.get("explanation", "")
                for ind in indicators
            ) else "No"
            timeline_points.append({
                "Event": "File System Created",
                "Timestamp": created_str,
                "Source": "File Metadata",
                "Anomaly": created_anomaly
            })

            # Event 2: File System Modified
            modified_dt = ts_res.get("modified")
            modified_str = format_evidence_ts(modified_dt)
            modified_anomaly = "Yes" if any(
                ind.get("type") == "Modified Before Created" or (ind.get("type") == "Future Timestamp" and "Modified" in ind.get("explanation", ""))
                for ind in indicators
            ) else "No"
            timeline_points.append({
                "Event": "File System Modified",
                "Timestamp": modified_str,
                "Source": "File Metadata",
                "Anomaly": modified_anomaly
            })

            # Event 3: File System Accessed
            accessed_dt = ts_res.get("accessed")
            accessed_str = format_evidence_ts(accessed_dt)
            accessed_anomaly = "Yes" if any(
                ind.get("type") == "Accessed Before Created" or (ind.get("type") == "Future Timestamp" and "Accessed" in ind.get("explanation", ""))
                for ind in indicators
            ) else "No"
            timeline_points.append({
                "Event": "File System Accessed",
                "Timestamp": accessed_str,
                "Source": "File Metadata",
                "Anomaly": accessed_anomaly
            })

        # Extract gaps from browser database analysis
        b_res = result.get("browser_result")
        if b_res and isinstance(b_res, dict):
            gaps = b_res.get("data", {}).get("gap_indicators", [])
            for g in gaps:
                gap_m = g.get('gap_duration_minutes', g.get('gap_minutes', 0))
                timeline_points.append({
                    "Event": f"Timeline Gap ({gap_m:.1f} min)",
                    "Timestamp": f"Between {g.get('start_time', 'N/A')} and {g.get('end_time', 'N/A')}",
                    "Source": "Browser History",
                    "Anomaly": "Yes"
                })

        # Extract indicators & gaps from Event Log analysis
        el_res = result.get("eventlog_result")
        if el_res and isinstance(el_res, dict):
            for ind in el_res.get("indicators", []):
                itype = ind.get("type", "Event Log Indicator")
                if itype == "Timeline Gap":
                    gap_mins = ind.get("gap_minutes", 0)
                    bt = ind.get("between", ("N/A", "N/A"))
                    timeline_points.append({
                        "Event": f"Timeline Gap ({gap_mins:.1f} min)",
                        "Timestamp": f"Between {bt[0]} and {bt[1]}",
                        "Source": "Windows Event Log",
                        "Anomaly": "Yes"
                    })
                else:
                    eid = ind.get("event_id", "N/A")
                    rec = ind.get("record_id", "N/A")
                    ts = ind.get("timestamp", "N/A")
                    timeline_points.append({
                        "Event": f"{itype} (Event ID {eid}, Record {rec})",
                        "Timestamp": str(ts),
                        "Source": ind.get("source", "Windows Event Log"),
                        "Anomaly": "Yes"
                    })

        if timeline_points:
            df_tl = pd.DataFrame(timeline_points)
            st.table(df_tl)
        else:
            st.markdown("""
            <div class="dark-panel" style="color:#cbd5e1;">
                No chronologically indexed timeline entries or gap anomalies extracted for this artifact type.
            </div>
            """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# PAGE 3: MODULE RESULTS
# -----------------------------------------------------------------------------
elif selected_page == "Module Results":
    st.markdown('<div class="page-heading">DETAILED MODULE RESULTS</div>', unsafe_allow_html=True)

    if st.session_state.pipeline_result is None:
        st.info("ℹ️ No evidence loaded. Please upload an evidence file on the **Investigation** page.")
    else:
        result = st.session_state.pipeline_result
        statuses = result.get("module_statuses", {})
        mod_results = result.get("module_results", {})

        all_modules = [
            "Timestamp Analysis",
            "Hidden File Check",
            "YARA Analysis",
            "Browser Artifact Analysis",
            "Event Log Analysis",
            "Memory Analysis (Volatility 3)"
        ]

        active_mod = st.session_state.selected_module or all_modules[0]

        mod_tab_choice = st.selectbox(
            "Select Module to Inspect:",
            all_modules,
            index=all_modules.index(active_mod) if active_mod in all_modules else 0
        )
        st.session_state.selected_module = mod_tab_choice

        st.markdown(f'<div class="section-heading">{mod_tab_choice}</div>', unsafe_allow_html=True)

        m_status = statuses.get(mod_tab_choice, "NOT_APPLICABLE")
        st.markdown(f"**Execution Status:** <span class='badge badge-success' style='font-size:16px;'>{m_status}</span>", unsafe_allow_html=True)

        m_data = mod_results.get(mod_tab_choice, {})

        if mod_tab_choice == "Timestamp Analysis":
            st.markdown("""
            **Analysis Scope:** Evaluates file system timestamp attributes (`Created`, `Modified`, `Accessed`) to detect timestomping anomalies.
            """)
            if m_data:
                col_t1, col_t2, col_t3 = st.columns(3)
                with col_t1:
                    st.metric("Created Timestamp", str(m_data.get("created", "N/A")))
                with col_t2:
                    st.metric("Modified Timestamp", str(m_data.get("modified", "N/A")))
                with col_t3:
                    st.metric("Accessed Timestamp", str(m_data.get("accessed", "N/A")))

                if m_data.get("anomaly_detected"):
                    indicators = m_data.get("indicators", [])
                    for ind in indicators:
                        ind_type = ind.get("type", "Timestomping Anomaly")
                        ind_exp = ind.get("explanation", "N/A")
                        pts = INDICATOR_WEIGHTS.get(ind_type, 20)
                        sev = severity_from_points(pts)

                        st.markdown(f"""
                        <div class="dark-panel" style="border-left: 4px solid #ef4444; margin-top: 15px; margin-bottom: 15px;">
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">FINDING</div>
                            <div style="font-size: 18px; color: #ffffff; font-weight: 700; margin-bottom: 8px;">{ind_type} Anomaly Detected</div>
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase; margin-top: 10px;">EXPLANATION</div>
                            <div style="font-size: 15px; color: #f1f5f9; margin-bottom: 12px;">{ind_exp}</div>
                            <div style="display: flex; gap: 24px; align-items: center;">
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">SEVERITY:</span>
                                    <span class="badge badge-high" style="margin-left: 6px;">{sev}</span>
                                </div>
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">POINTS:</span>
                                    <span class="tech-mono" style="color: #60a5fa; font-weight: 700; margin-left: 6px;">{pts}</span>
                                </div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("✅ Timestamps appear chronologically consistent.")

        elif mod_tab_choice == "Hidden File Check":
            st.markdown("""
            **Analysis Scope:** Inspects file system attributes to identify hidden or hidden-system file markers used for concealment.
            """)
            if m_data:
                st.metric("Hidden Attribute Set", "TRUE" if m_data.get("is_hidden") else "FALSE")
                st.markdown(f"**Explanation:** {m_data.get('explanation', 'N/A')}")

        elif mod_tab_choice == "YARA Analysis":
            st.markdown("""
            **Analysis Scope:** Scans evidence byte streams against compiled anti-forensic YARA rules (detecting log cleaners, timestompers, and wipers).
            """)
            if m_data:
                matches = m_data.get("matches", [])
                st.metric("YARA Rules Matched", len(matches))
                if matches:
                    for match in matches:
                        rule_name = match.get("rule", match.get("rule_name", "YARA Rule Match"))
                        exp = match.get("explanation", match.get("description", "Anti-forensic signature detected."))
                        st.markdown(f"""
                        <div class="dark-panel" style="border-left: 4px solid #ef4444; margin-top: 15px; margin-bottom: 15px;">
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">FINDING</div>
                            <div style="font-size: 18px; color: #ffffff; font-weight: 700; margin-bottom: 8px;">YARA Match: {rule_name}</div>
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase; margin-top: 10px;">EXPLANATION</div>
                            <div style="font-size: 15px; color: #f1f5f9; margin-bottom: 12px;">{exp}</div>
                            <div style="display: flex; gap: 24px; align-items: center;">
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">SEVERITY:</span>
                                    <span class="badge badge-high" style="margin-left: 6px;">HIGH</span>
                                </div>
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">POINTS:</span>
                                    <span class="tech-mono" style="color: #60a5fa; font-weight: 700; margin-left: 6px;">25</span>
                                </div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("✅ No anti-forensic YARA rule signatures matched.")

        elif mod_tab_choice == "Browser Artifact Analysis":
            st.markdown("""
            **Analysis Scope:** Analyzes Chromium/Firefox SQLite history databases for visit timelines, deleted history gaps, and table modifications.
            """)
            if m_status in ["SUCCESS", "CORRUPTED", "FAILED"]:
                b_info = m_data.get("data", {})
                col_b1, col_b2, col_b3 = st.columns(3)
                with col_b1:
                    st.metric("Total Visits Extracted", b_info.get("total_visits_extracted", 0))
                with col_b2:
                    st.metric("Timeline Gaps Detected", b_info.get("total_gaps_detected", 0))
                with col_b3:
                    st.metric("Schema Type", m_data.get("metadata", {}).get("schema_type", "N/A"))

                gaps = b_info.get("gap_indicators", [])
                if gaps:
                    st.warning(f"⚠️ Detected {len(gaps)} potential anti-forensic activity gap(s) in browser database.")
                    for g in gaps:
                        g_type = g.get("type", "Timeline Gap")
                        g_exp = g.get("explanation", "Potential anti-forensic activity gap detected.")
                        st.markdown(f"""
                        <div class="dark-panel" style="border-left: 4px solid #eab308; margin-top: 15px; margin-bottom: 15px;">
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">FINDING</div>
                            <div style="font-size: 18px; color: #ffffff; font-weight: 700; margin-bottom: 8px;">{g_type}</div>
                            <div style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase; margin-top: 10px;">EXPLANATION</div>
                            <div style="font-size: 15px; color: #f1f5f9; margin-bottom: 12px;">{g_exp}</div>
                            <div style="display: flex; gap: 24px; align-items: center;">
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">SEVERITY:</span>
                                    <span class="badge badge-medium" style="margin-left: 6px;">MEDIUM</span>
                                </div>
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 600;">POINTS:</span>
                                    <span class="tech-mono" style="color: #60a5fa; font-weight: 700; margin-left: 6px;">15</span>
                                </div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                visits = b_info.get("visits_sample", [])
                if visits:
                    st.markdown("**Sample Extracted Browser Visits:**")
                    st.dataframe(pd.DataFrame(visits))
            else:
                st.info("Module Not Applicable for this evidence file type.")

        elif mod_tab_choice == "Event Log Analysis":
            st.markdown("""
            **Analysis Scope:** Parses Windows `.evtx` event logs and analyzes security-relevant events, including Security log clearing (Event ID 1102), Event Log service shutdown (Event ID 1100), audit policy changes (Event ID 4719), and potential timeline gaps between event records.
            """)
            if m_status == "SUCCESS":
                indicators = m_data.get("indicators", [])
                total_events = m_data.get("total_events_analyzed", len(indicators))
                security_findings = [ind for ind in indicators if ind.get("type") != "Timeline Gap"]
                gap_findings = [ind for ind in indicators if ind.get("type") == "Timeline Gap"]

                # Group indicators by distinct category to compute and display distinct risk contribution
                distinct_categories = {}
                for ind in indicators:
                    itype = ind.get("type", "Event Log Anomaly")
                    if itype not in distinct_categories:
                        distinct_categories[itype] = []
                    distinct_categories[itype].append(ind)

                eventlog_risk_pts = sum(INDICATOR_WEIGHTS.get(cat, 0) for cat in distinct_categories.keys())

                col_e1, col_e2, col_e3, col_e4 = st.columns(4)
                with col_e1:
                    st.metric("Total Events Parsed", total_events)
                with col_e2:
                    st.metric("Findings Detected", len(security_findings))
                with col_e3:
                    st.metric("Timeline Gaps Detected", len(gap_findings))
                with col_e4:
                    st.metric("Event Log Risk Contribution", f"+{eventlog_risk_pts} pts")

                if indicators:
                    st.markdown('<div class="section-heading" style="font-size:18px; margin-top:16px;">Detected Anti-Forensics Indicators & Occurrences</div>', unsafe_allow_html=True)

                    for cat_name, occ_list in distinct_categories.items():
                        cat_pts = INDICATOR_WEIGHTS.get(cat_name, 20)
                        cat_sev = severity_from_points(cat_pts)
                        sev_badge_cls = "badge-high" if cat_sev == "HIGH" else ("badge-medium" if cat_sev == "MEDIUM" else "badge-low")
                        border_color = "#ef4444" if cat_sev == "HIGH" else ("#eab308" if cat_sev == "MEDIUM" else "#22c55e")

                        st.markdown(f"""
                        <div class="dark-panel" style="border-left: 4px solid {border_color}; margin-top: 14px; margin-bottom: 14px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <div>
                                    <span style="font-size: 13px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">INDICATOR CATEGORY</span>
                                    <div style="font-size: 19px; color: #ffffff; font-weight: 700;">{cat_name}</div>
                                </div>
                                <div style="text-align: right;">
                                    <span class="badge {sev_badge_cls}">{cat_sev}</span>
                                    <div style="font-size: 14px; color: #60a5fa; font-weight: 700; margin-top: 4px;" class="tech-mono">Risk Contribution: +{cat_pts} pts</div>
                                </div>
                            </div>
                            <div style="font-size: 14px; color: #cbd5e1; margin-bottom: 12px;">
                                <strong>Occurrences:</strong> <span class="tech-mono" style="color:#ffffff; font-weight:700;">{len(occ_list)}</span> &nbsp;|&nbsp; 
                                <strong>Base Weight:</strong> <span class="tech-mono" style="color:#60a5fa;">{cat_pts} pts</span> <em>(applied once per distinct indicator category)</em>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                        # Render individual occurrence breakdown
                        if cat_name != "Timeline Gap":
                            for idx, ind in enumerate(occ_list, 1):
                                eid_val = ind.get("event_id", "N/A")
                                rec_val = ind.get("record_id", "N/A")
                                chan_val = ind.get("channel", "Security")
                                computer_val = ind.get("computer", "Unknown")
                                source_val = ind.get("source", "Unknown")
                                ts_val = ind.get("timestamp", "N/A")
                                exp_val = ind.get("explanation", "N/A")
                                event_details = ind.get("message", "")

                                st.markdown(f"""
                                <div style="background-color: #151a24; border: 1px solid #252d3d; border-radius: 6px; padding: 14px; margin-bottom: 10px; margin-left: 12px;">
                                    <div style="font-size: 15px; color: #ffffff; font-weight: 600; margin-bottom: 6px;">
                                        Occurrence #{idx} &mdash; Event ID: <span class="tech-mono" style="color:#38bdf8;">{eid_val}</span> (Record ID: <span class="tech-mono" style="color:#60a5fa;">{rec_val}</span>)
                                    </div>
                                    <div style="font-size: 13px; color: #94a3b8; font-family: monospace; margin-bottom: 6px;">
                                        Timestamp: <span style="color:#f1f5f9;">{ts_val}</span> &nbsp;|&nbsp; Channel: <span style="color:#f1f5f9;">{chan_val}</span>
                                    </div>
                                    <div style="font-size: 13px; color: #94a3b8; font-family: monospace; margin-bottom: 6px;">
                                        Computer: <span style="color:#f1f5f9;">{computer_val}</span> &nbsp;|&nbsp; Source / Provider: <span style="color:#f1f5f9;">{source_val}</span>
                                    </div>
                                    <div style="font-size: 14px; color: #cbd5e1; line-height: 1.4; margin-bottom: 6px;"><strong>Event Data:</strong> {event_details or 'No event data available.'}</div>
                                    <div style="font-size: 14px; color: #e2e8f0; line-height: 1.4;">{exp_val}</div>
                                </div>
                                """, unsafe_allow_html=True)
                        else:
                            # Render timeline gap occurrences
                            for idx, gap in enumerate(occ_list, 1):
                                gap_mins = gap.get("gap_minutes", 0)
                                between_range = gap.get("between", ("N/A", "N/A"))
                                from_rec = gap.get("from_record_id", "N/A")
                                to_rec = gap.get("to_record_id", "N/A")
                                from_eid = gap.get("from_event_id", "N/A")
                                to_eid = gap.get("to_event_id", "N/A")
                                exp_val = gap.get("explanation", "Potential timeline gap detected.")

                                st.markdown(f"""
                                <div style="background-color: #151a24; border: 1px solid #252d3d; border-radius: 6px; padding: 14px; margin-bottom: 10px; margin-left: 12px;">
                                    <div style="font-size: 15px; color: #ffffff; font-weight: 600; margin-bottom: 6px;">
                                        Timeline Gap #{idx} &mdash; <span class="tech-mono" style="color:#eab308;">{gap_mins:.1f} minutes</span>
                                    </div>
                                    <div style="font-size: 13px; color: #94a3b8; font-family: monospace; margin-bottom: 6px;">
                                        Between: <span style="color:#f1f5f9;">{between_range[0]}</span> &rarr; <span style="color:#f1f5f9;">{between_range[1]}</span>
                                    </div>
                                    <div style="font-size: 13px; color: #94a3b8; font-family: monospace; margin-bottom: 6px;">
                                        Bounding Records: <span style="color:#38bdf8;">Record {from_rec}</span> (Event ID {from_eid}) &rarr; <span style="color:#38bdf8;">Record {to_rec}</span> (Event ID {to_eid})
                                    </div>
                                    <div style="font-size: 14px; color: #e2e8f0; line-height: 1.4;">{exp_val}</div>
                                </div>
                                """, unsafe_allow_html=True)
                else:
                    st.success("✅ No anti-forensic indicators detected in Event Log.")
            else:
                st.info("Module Not Applicable for this evidence file type.")

        elif mod_tab_choice == "Memory Analysis (Volatility 3)":
            st.markdown("""
            **Analysis Scope:** Evaluates RAM memory captures using Volatility 3 framework for injected code and unlinked processes.
            """)
            st.info(f"Memory Analysis Status: {m_status}. {m_data.get('notes', m_data.get('error', 'N/A'))}")


# -----------------------------------------------------------------------------
# PAGE 4: FINDINGS TABLE
# -----------------------------------------------------------------------------
elif selected_page == "Findings Table":
    st.markdown('<div class="page-heading">STRUCTURED FORENSIC FINDINGS</div>', unsafe_allow_html=True)

    if st.session_state.pipeline_result is None:
        st.info("ℹ️ No evidence loaded. Upload evidence on the **Investigation** page.")
    else:
        findings = st.session_state.pipeline_result.get("findings", [])
        
        if findings:
            st.markdown(f"Total Anti-Forensic Indicators Identified: **{len(findings)}**")

            rows_html = ""
            for f in findings:
                sev = f.get("severity", "LOW").upper()
                badge_cls = "badge-high" if sev == "HIGH" else ("badge-medium" if sev == "MEDIUM" else "badge-low")
                pts = f.get("points", "+20" if sev == "HIGH" else ("+15" if sev == "MEDIUM" else "+10"))
                
                rows_html += f"""<tr>
<td class="tech-mono" style="color:#60a5fa; font-weight:700;">{f.get('finding_id', 'AF-00000000')}</td>
<td style="font-weight:600;">{f.get('type', 'Unknown')}</td>
<td><span class="badge {badge_cls}">{sev}</span></td>
<td class="tech-mono">{pts}</td>
<td style="line-height:1.4;">{f.get('reason', '')}</td>
<td style="color:#cbd5e1;">{f.get('source', 'System')}</td>
<td style="color:#cbd5e1;">{f.get('evidence', 'Evidence File')}</td>
</tr>"""

            table_html = f"""<table class="forensic-table">
<thead>
<tr>
<th>Finding ID</th>
<th>Indicator</th>
<th>Severity</th>
<th>Points</th>
<th>Reason / Observation</th>
<th>Source</th>
<th>Evidence Reference</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>"""
            st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.success("✅ Clean Evidence File — No anti-forensic anomaly findings were triggered.")


# -----------------------------------------------------------------------------
# PAGE 5: INVESTIGATION HISTORY (PERSISTENT RE-LOADABLE CASES)
# -----------------------------------------------------------------------------
elif selected_page == "Investigation History":
    st.markdown('<div class="page-heading">PERSISTENT INVESTIGATION HISTORY</div>', unsafe_allow_html=True)

    history_records = get_investigation_history()

    if not history_records:
        st.info("No prior investigations stored in history database.")
    else:
        st.markdown(f"Total Stored Investigations: **{len(history_records)}**")

        df_hist = pd.DataFrame([
            {
                "Timestamp": r.get("timestamp"),
                "Case ID": r.get("case_id"),
                "Evidence ID": r.get("evidence_id"),
                "Investigator": r.get("investigator"),
                "Filename": r.get("filename"),
                "Artifact Type": r.get("artifact_type"),
                "Risk Score": f"{r.get('risk_score')}/100 ({r.get('risk_level')})",
                "Status": r.get("status")
            }
            for r in history_records
        ])
        
        st.dataframe(df_hist, use_container_width=True)

        st.markdown('<div class="section-heading">Inspect / Reload Historical Investigation</div>', unsafe_allow_html=True)
        
        case_options = [f"{r['case_id']} | {r['evidence_id']} ({r['filename']})" for r in history_records]
        selected_case_str = st.selectbox("Select Historical Case:", case_options)

        if st.button("Load Selected Case Results"):
            idx = case_options.index(selected_case_str)
            target_record = history_records[idx]

            st.session_state.case_id = target_record["case_id"]
            st.session_state.evidence_id = target_record["evidence_id"]
            st.session_state.investigator_name = target_record["investigator"]
            st.session_state.pipeline_result = target_record["pipeline_result"]
            st.session_state.evidence_meta = target_record["evidence_meta"]

            st.success(f"Loaded investigation details for {target_record['case_id']}.")
            st.session_state.active_nav_page = "Analysis Overview"
            st.rerun()


# -----------------------------------------------------------------------------
# PAGE 6: AUDIT LOG (SYSTEM & INVESTIGATOR ACTIONS)
# -----------------------------------------------------------------------------
elif selected_page == "Audit Log":
    st.markdown('<div class="page-heading">SYSTEM & INVESTIGATOR AUDIT LOG</div>', unsafe_allow_html=True)

    audit_logs = get_audit_logs()

    if not audit_logs:
        st.info("No audit log events recorded yet.")
    else:
        st.markdown(f"Total Audit Trail Entries: **{len(audit_logs)}**")

        rows_html = ""
        for log in audit_logs:
            rows_html += f"""<tr>
<td class="tech-mono" style="color:#94a3b8; font-size:15px;">{log.get('timestamp')}</td>
<td style="font-weight:600; color:#60a5fa;">{log.get('action')}</td>
<td class="tech-mono">{log.get('case_id')}</td>
<td class="tech-mono">{log.get('evidence_id')}</td>
<td>{log.get('investigator')}</td>
<td style="color:#cbd5e1;">{log.get('details')}</td>
</tr>"""

        audit_table = f"""<table class="forensic-table">
<thead>
<tr>
<th>Timestamp (UTC)</th>
<th>Action</th>
<th>Case ID</th>
<th>Evidence ID</th>
<th>Investigator</th>
<th>Details</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>"""
        st.markdown(audit_table, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# PAGE 7: REPORTS & EXPORT
# -----------------------------------------------------------------------------
elif selected_page == "Reports & Export":
    st.markdown('<div class="page-heading">OFFICIAL FORENSIC EXAMINATION REPORTS</div>', unsafe_allow_html=True)

    if st.session_state.pipeline_result is None:
        st.info("ℹ️ No evidence loaded. Upload evidence on the **Investigation** page.")
    else:
        result = st.session_state.pipeline_result
        meta = st.session_state.evidence_meta

        case_meta = {
            "case_id": st.session_state.case_id,
            "evidence_id": st.session_state.evidence_id,
            "analyst": st.session_state.investigator_name
        }

        json_report = generate_json_report(result, case_meta)
        html_report = generate_html_report(result, case_meta)

        report_log_key = f"report_logged_{st.session_state.case_id}_{st.session_state.evidence_id}"
        if not st.session_state.get(report_log_key):
            add_audit_log_entry(
                action="Report Generated",
                case_id=st.session_state.case_id,
                evidence_id=st.session_state.evidence_id,
                investigator=st.session_state.investigator_name,
                details="JSON & HTML reports compiled."
            )
            st.session_state[report_log_key] = True

        st.markdown('<div class="section-heading">Download Reports</div>', unsafe_allow_html=True)
        col_e1, col_e2 = st.columns(2)

        with col_e1:
            st.download_button(
                label="📄 Download Official HTML Report",
                data=html_report.encode("utf-8"),
                file_name=f"Forensic_Report_{st.session_state.case_id}.html",
                mime="text/html",
                use_container_width=True
            )

        with col_e2:
            st.download_button(
                label="💾 Download Structured JSON Report",
                data=json_report.encode("utf-8"),
                file_name=f"Forensic_Report_{st.session_state.case_id}.json",
                mime="application/json",
                use_container_width=True
            )


# -----------------------------------------------------------------------------
# PAGE 8: HELP
# -----------------------------------------------------------------------------
elif selected_page == "Help":
    st.markdown('<div class="page-heading">FORENSIC SYSTEM HELP & REFERENCE GUIDE</div>', unsafe_allow_html=True)

    st.markdown("""
    ### System Architecture & Workflow
    The **Automated Anti-Forensics Detection System** automatically ingests digital evidence artifacts, computes cryptographic hashes, classifies artifact types, routes to applicable detection modules, extracts indicators of timestomping, log clearing, hidden attribute usage, or browser activity gaps, and aggregates an overall risk score.

    ### Workflow Steps:
    1. **Investigator Information**: Enter investigator identity to unlock evidence controls.
    2. **Evidence Identification**: Cryptographic hashing (SHA-256) and artifact type matching.
    3. **Automated Pipeline**: Route to Timestamp, Hidden File, YARA, Browser, Event Log, and Memory analysis.
    4. **Risk Scoring**: Risk points aggregated into LOW (0-29), MEDIUM (30-59), and HIGH (60-100) levels.
    5. **Report Generation**: Export standalone HTML and JSON forensic examination reports.
    """)
