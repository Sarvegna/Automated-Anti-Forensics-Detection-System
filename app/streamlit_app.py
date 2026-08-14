import streamlit as st
import sys
import os
import tempfile
import uuid
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.integrity import calculate_sha256
from core.validation import validate_evidence_file
from core.timestamp_analysis import analyze_timestamps
from core.hidden_file_detection import check_hidden_file
from core.risk_scoring import calculate_risk_score

st.set_page_config(page_title="Anti-Forensics Detection System", layout="wide", page_icon="🔍")

st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
    html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif; }

    .stApp {
        background-color: #12141a;
        background-image:
            radial-gradient(circle at 15% 0%, #5cd6f514 0%, transparent 35%),
            radial-gradient(circle at 85% 10%, #3ddc9710 0%, transparent 30%),
            linear-gradient(#ffffff08 1px, transparent 1px),
            linear-gradient(90deg, #ffffff08 1px, transparent 1px);
        background-size: auto, auto, 28px 28px, 28px 28px;
    }

    .tag {
        font-family: 'JetBrains Mono', monospace;
        color: #5cd6f5;
        font-size: 13px;
        letter-spacing: 2px;
        border: 1px solid #5cd6f555;
        padding: 2px 10px;
        border-radius: 3px;
        display: inline-block;
        margin-bottom: 8px;
    }

    h1 {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        letter-spacing: -1px;
        font-size: 48px;
        background: linear-gradient(180deg, #ffffff 0%, #c9ccd3 60%, #8b90a0 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-shadow: 0 2px 0 #00000040, 0 8px 24px #5cd6f530;
        filter: drop-shadow(0 0 18px #5cd6f522);
        margin-bottom: 4px;
    }

    .title-underline {
      height: 2px;
      width: 100%;
      max-width: 640px;
      background: linear-gradient(90deg, #5cd6f5 0%, #5cd6f560 40%, transparent 100%);
      margin: 4px 0 20px 0;
      box-shadow: 0 0 12px #5cd6f588;
    }

    h2 {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 600;
        color: #f2f3f5;
        font-size: 22px;
        border-left: 3px solid #5cd6f5;
        padding-left: 12px;
        margin-top: 28px;
    }

    .mono-panel {
        font-family: 'JetBrains Mono', monospace;
        background: linear-gradient(145deg, #1e222c, #191c24);
        border: 1px solid #2a2e3a;
        border-radius: 8px;
        padding: 16px 20px;
        color: #d7dae0;
        font-size: 14px;
        box-shadow: 0 8px 20px -8px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.03);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .mono-panel:hover {
        transform: translateY(-2px);
        box-shadow: 0 14px 28px -10px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.05);
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, #1e222c, #191c24);
        border: 1px solid #2a2e3a;
        border-radius: 8px;
        padding: 14px;
        box-shadow: 0 8px 20px -10px rgba(0,0,0,0.6);
    }
    div[data-testid="stMetric"] label { color: #8b90a0 !important; font-family: 'JetBrains Mono', monospace; }
    div[data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace; color: #f2f3f5; }

    .stTextInput input {
        font-family: 'JetBrains Mono', monospace;
        background-color: #1c1f28;
        color: #5cd6f5;
        border: 1px solid #2a2e3a;
    }

    .stAlert { border-radius: 6px; font-family: 'Space Grotesk', sans-serif; }

    [data-testid="stFileUploader"] {
        border: 1px dashed #5cd6f566;
        border-radius: 8px;
        padding: 8px;
        background-color: #1a1d24;
        box-shadow: 0 8px 20px -12px rgba(0,0,0,0.6);
    }

    .caption-text {
        font-family: 'JetBrains Mono', monospace;
        color: #6b7080;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<span class="tag">FORENSIC INVESTIGATION TERMINAL</span>', unsafe_allow_html=True)
st.markdown('<h1>Automated Anti-Forensics Detection System</h1>', unsafe_allow_html=True)
st.markdown('<div class="title-underline"></div>', unsafe_allow_html=True)
st.markdown('<p class="caption-text">Rule-based indicator detection · Explainable risk scoring · Investigator review required</p>', unsafe_allow_html=True)

st.markdown('<span class="tag">[ 01 ] CASE INFORMATION</span>', unsafe_allow_html=True)

if "case_id" not in st.session_state:
    st.session_state.case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
if "evidence_id" not in st.session_state:
    st.session_state.evidence_id = f"EVID-{str(uuid.uuid4())[:8].upper()}"

col1, col2, col3 = st.columns(3)
with col1:
    st.text_input("CASE ID", value=st.session_state.case_id, key="case_id_display")
with col2:
    st.text_input("EVIDENCE ID", value=st.session_state.evidence_id, key="evidence_id_display")
with col3:
    st.text_input("ANALYST", placeholder="Enter your name", key="analyst_name")

st.markdown('<span class="tag">[ 02 ] EVIDENCE UPLOAD</span>', unsafe_allow_html=True)
uploaded_file = st.file_uploader("Drop an evidence file to begin analysis", label_visibility="visible")

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = tmp.name

    is_valid, validation_message = validate_evidence_file(temp_path)

    if not is_valid:
        st.error(f"VALIDATION FAILED — {validation_message}")
    else:
        st.success(f"EVIDENCE VALIDATED — {uploaded_file.name}")

        st.markdown('<span class="tag">[ 03 ] INTEGRITY VERIFICATION</span>', unsafe_allow_html=True)
        file_hash = calculate_sha256(temp_path)
        st.markdown(f'<div class="mono-panel">SHA-256<br>{file_hash}<br><br>STATUS: <span style="color:#3ddc97">✓ VERIFIED</span></div>', unsafe_allow_html=True)

        st.markdown('<span class="tag">[ 04 ] TIMESTAMP ANALYSIS</span>', unsafe_allow_html=True)
        timestamp_result = analyze_timestamps(temp_path)
        c1, c2, c3 = st.columns(3)
        c1.metric("CREATED", str(timestamp_result["created"])[:19])
        c2.metric("MODIFIED", str(timestamp_result["modified"])[:19])
        c3.metric("ACCESSED", str(timestamp_result["accessed"])[:19])

        if timestamp_result["anomaly_detected"]:
            st.warning(timestamp_result["explanation"])
        else:
            st.info(timestamp_result["explanation"])

        st.markdown('<span class="tag">[ 05 ] HIDDEN ATTRIBUTE CHECK</span>', unsafe_allow_html=True)
        hidden_result = check_hidden_file(temp_path)
        if hidden_result["is_hidden"]:
            st.warning(hidden_result["explanation"])
        else:
            st.info(hidden_result["explanation"])

        st.markdown('<span class="tag">[ 06 ] RISK ASSESSMENT</span>', unsafe_allow_html=True)
        risk_result = calculate_risk_score(
            timestamp_result=timestamp_result,
            hidden_file_result=hidden_result
        )

        risk_colors = {"LOW": "#3ddc97", "MEDIUM": "#5cd6f5", "HIGH": "#ff6b5c"}
        rc = risk_colors[risk_result["risk_level"]]

        st.markdown(f"""
        <div style="background: linear-gradient(145deg, #1e222c, #191c24); border:1px solid {rc}; border-radius:10px; padding:20px; display:flex; justify-content:space-between; align-items:center; box-shadow: 0 12px 28px -10px rgba(0,0,0,0.7);">
            <div>
                <div style="font-family:'JetBrains Mono',monospace; color:#8b90a0; font-size:13px;">RISK SCORE</div>
                <div style="font-family:'JetBrains Mono',monospace; color:#f2f3f5; font-size:36px; font-weight:700;">{risk_result['score']} / 100</div>
            </div>
            <div style="font-family:'Space Grotesk',sans-serif; color:{rc}; font-size:28px; font-weight:700; letter-spacing:2px; text-shadow: 0 0 16px {rc}55;">
                {risk_result['risk_level']}
            </div>
        </div>
        """, unsafe_allow_html=True)

        if risk_result["contributing_indicators"]:
            st.markdown("**Contributing Indicators**")
            for ind in risk_result["contributing_indicators"]:
                st.markdown(f'<div class="mono-panel" style="margin-bottom:6px;">+{ind["points"]} &nbsp;·&nbsp; {ind["type"]}<br><span style="color:#8b90a0; font-size:12px;">{ind["explanation"]}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="caption-text">No indicators contributed to this score.</p>', unsafe_allow_html=True)

        st.markdown('<p class="caption-text">⚠ This is an investigative aid. Findings represent potential indicators requiring investigator review, not confirmed evidence manipulation.</p>', unsafe_allow_html=True)

    os.unlink(temp_path)
else:
    st.markdown('<p class="caption-text">Awaiting evidence upload.</p>', unsafe_allow_html=True)