"""
SIH26106 - Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Streamlit Dashboard

Run with: streamlit run dashboard.py
"""

import streamlit as st
import tempfile
import os
from risk_scorer import score_email

st.set_page_config(page_title="Email Forensic Intelligence", page_icon="🕵️", layout="wide")

st.title("🕵️ Email Threat Detection & Forensic Intelligence Platform")
st.caption("SIH26106 — AICTE | Prototype")

uploaded = st.file_uploader("Upload a .eml file", type=["eml"])
body_text = st.text_area(
    "Paste email body text (for language analysis — .eml body extraction can be added later)",
    height=100,
    placeholder="Paste the plain-text body of the email here...",
)

if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    result = score_email(tmp_path, body_text)
    os.unlink(tmp_path)

    score = result["score"]
    verdict = result["verdict"]

    color = "🔴" if score >= 70 else "🟡" if score >= 40 else "🟢"

    col1, col2 = st.columns([1, 2])
    with col1:
        st.metric("Risk Score", f"{score}/100")
    with col2:
        st.subheader(f"{color} {verdict}")

    st.progress(score / 100)

    st.subheader("Why this score")
    for reason in result["reasons"]:
        st.write(f"- {reason}")
    if not result["reasons"]:
        st.write("No risk indicators found.")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Auth Results", "Sender Mismatch", "Origin & Geolocation", "Domain Age", "Relay Chain"]
    )

    with tab1:
        st.json(result["auth_results"])

    with tab2:
        st.json(result["sender_mismatch"])

    with tab3:
        st.write(f"**Originating IP:** {result['originating_ip']}")
        st.json(result["geolocation"])

    with tab4:
        st.json(result["domain_age"])

    with tab5:
        st.write(f"**Hops traced:** {result['hop_count']}")
        for hop in result["relay_chain"]:
            st.text(f"Hop {hop['hop_index']}: {hop['raw'][:150]}...")
else:
    st.info("Upload a .eml file to begin analysis. A sample phishing email is in sample_emails/phishing_sample.eml")
