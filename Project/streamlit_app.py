from __future__ import annotations

import requests
import streamlit as st


st.set_page_config(page_title="Security Advisory Digest", layout="wide")
API_URL = st.sidebar.text_input("API URL", "http://localhost:8000")
st.title("Security Advisory Digest")

page = st.sidebar.radio("Pages", ["Upload Inventory", "Run Scan", "View Findings", "Download Report"])

if "findings" not in st.session_state:
    st.session_state.findings = []
if "report" not in st.session_state:
    st.session_state.report = ""

if page == "Upload Inventory":
    upload = st.file_uploader("Inventory YAML", type=["yaml", "yml"])
    if upload and st.button("Upload"):
        with st.spinner("Uploading inventory..."):
            response = requests.post(
                f"{API_URL}/inventory/upload",
                files={"file": (upload.name, upload.getvalue(), "application/x-yaml")},
                timeout=30,
            )
        if response.ok:
            st.success("Inventory uploaded.")
        else:
            st.error(response.text)

elif page == "Run Scan":
    if st.button("Run Scan"):
        with st.spinner("Searching advisories..."):
            response = requests.post(f"{API_URL}/scan", timeout=60)
        if response.ok:
            st.session_state.findings = response.json()
            st.success(f"Found {len(st.session_state.findings)} finding(s).")
        else:
            st.error(response.text)

elif page == "View Findings":
    findings = st.session_state.findings
    if findings:
        st.dataframe(findings, use_container_width=True)
    else:
        st.info("Run a scan to view findings.")

elif page == "Download Report":
    if st.button("Generate Report"):
        with st.spinner("Generating digest with Ollama..."):
            response = requests.get(f"{API_URL}/report", timeout=180)
        if response.ok:
            st.session_state.report = response.text
        else:
            st.error(response.text)
    if st.session_state.report:
        st.markdown(st.session_state.report)
        st.download_button("Download Markdown", st.session_state.report, "security_advisory_digest.md")
