import os
import streamlit as st
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector
from reporting.pdf_generator import PDFReportGenerator
from core.auth import AuthManager
from core.recon import ReconEngine
from engine.cve_lookup import VulnerabilityIntelligence

# Page Configuration
st.set_page_config(page_title="VulnForge Portal", layout="wide", page_icon="🛡️")

# Initialize Core Services & Authentication Manager
db = DatabaseManager()
validator = ScopeValidator()
inspector = SecurityInspector()
pdf_gen = PDFReportGenerator()
auth_mgr = AuthManager()
recon_engine = ReconEngine(validator)
vuln_intel = VulnerabilityIntelligence()

# Initialize Session State
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_info" not in st.session_state:
    st.session_state["user_info"] = None

# -----------------------------------------------------------------------------
# LOGIN & USER REGISTRATION GATEWAY
# -----------------------------------------------------------------------------
def render_login_screen():
    st.title("🛡️ VulnForge VAPT Platform")
    st.caption("SecOps Vulnerability Assessment & Evidence Management System")
    st.divider()

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab_login, tab_register = st.tabs(["🔐 Sign In", "👤 Create User Account"])

        with tab_login:
            st.subheader("Account Login")
            login_username = st.text_input("Username", key="login_user")
            login_password = st.text_input("Password", type="password", key="login_pass")

            if st.button("Log In", use_container_width=True, type="primary"):
                if login_username and login_password:
                    user = auth_mgr.authenticate_user(login_username, login_password)
                    if user:
                        st.session_state["authenticated"] = True
                        st.session_state["user_info"] = user
                        st.success(f"Authenticated as {user['username']} ({user['role']})")
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")
                else:
                    st.warning("Please enter both username and password.")

        with tab_register:
            st.subheader("Register User")
            reg_username = st.text_input("New Username", key="reg_user")
            reg_password = st.text_input("New Password", type="password", key="reg_pass")
            reg_role = st.selectbox("Role Assignment", ["Admin", "Analyst", "Viewer"], key="reg_role")

            if st.button("Register Account", use_container_width=True):
                if reg_username and reg_password:
                    success = auth_mgr.register_user(reg_username, reg_password, reg_role)
                    if success:
                        st.success(f"Account '{reg_username}' registered! You can now log in.")
                    else:
                        st.error("Registration failed. Username may already exist.")
                else:
                    st.warning("All fields are required.")

# Direct unauthenticated users to the login gateway
if not st.session_state["authenticated"]:
    render_login_screen()
    st.stop()

# -----------------------------------------------------------------------------
# AUTHENTICATED USER SESSION & SIDEBAR NAVIGATION
# -----------------------------------------------------------------------------
current_user = st.session_state["user_info"]

st.sidebar.title("🛡️ VulnForge Platform")
st.sidebar.markdown(f"**User:** `{current_user['username']}`")
st.sidebar.markdown(f"**Role:** `{current_user['role']}`")

if st.sidebar.button("Log Out", type="secondary"):
    st.session_state["authenticated"] = False
    st.session_state["user_info"] = None
    st.rerun()

st.sidebar.divider()

# Role-Based Navigation Access Control
available_pages = ["Overview Dashboard", "Export PDF Reports"]

if current_user["role"] in ["Admin", "Analyst"]:
    available_pages.insert(1, "Asset Reconnaissance")
    available_pages.insert(2, "Target Scope Control")
    available_pages.insert(3, "Run Assessment")
    available_pages.insert(4, "Analyst Triaging")
    available_pages.insert(5, "Remediation Retest")

nav_choice = st.sidebar.radio("Navigation Menu", available_pages)

# -----------------------------------------------------------------------------
# PAGE 1: OVERVIEW DASHBOARD
# -----------------------------------------------------------------------------
if nav_choice == "Overview Dashboard":
    st.title("📊 Security Operations Overview")
    
    targets = db.fetch_all_targets()
    findings = db.fetch_vulnerabilities_overview()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Registered Target Assets", len(targets))
    col2.metric("Total Findings Recorded", len(findings))
    col3.metric("Unverified Findings", sum(1 for f in findings if f["review_state"] == "Unverified"))
    col4.metric("Confirmed Issues", sum(1 for f in findings if f["review_state"] == "Confirmed Vulnerability"))

    st.divider()
    st.subheader("Discovered Vulnerability Findings")
    if findings:
        st.dataframe(findings, use_container_width=True)
    else:
        st.info("No security observations recorded in database yet.")

# -----------------------------------------------------------------------------
# PAGE: ASSET RECONNAISSANCE & THREAT INTELLIGENCE
# -----------------------------------------------------------------------------
elif nav_choice == "Asset Reconnaissance":
    st.title("🔎 Automated Asset Discovery & Reconnaissance")
    st.caption("Passive CT log subdomain discovery, async port scanning, stack fingerprinting, and live CVE/EPSS intelligence.")

    targets = db.fetch_all_targets()
    if not targets:
        st.warning("No targets authorized. Please register a target in Target Scope Control first.")
    else:
        target_map = {f"{t['label']} ({t['target_url']})": t for t in targets}
        selected_key = st.selectbox("Select Target Asset for Reconnaissance", list(target_map.keys()))
        target = target_map[selected_key]

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🌐 Passive Subdomain Discovery")
            if st.button("Run crt.sh Discovery"):
                with st.spinner("Querying CT logs & verifying scope..."):
                    subs = recon_engine.discover_subdomains(target["target_url"])
                    st.success(f"Discovered {len(subs)} authorized asset(s).")
                    st.write(subs)

        with col2:
            st.subheader("🔌 Async Port Scanner")
            if st.button("Scan Common TCP Ports"):
                with st.spinner("Executing async TCP probe..."):
                    open_ports = recon_engine.run_port_scan(target["target_url"])
                    if open_ports:
                        st.success(f"Found {len(open_ports)} open port(s).")
                        st.table(open_ports)
                    else:
                        st.info("No common open ports detected.")

        st.divider()
        st.subheader("🧩 Technology Stack Fingerprinting")
        if st.button("Fingerprint Web Tech Stack"):
            with st.spinner("Analyzing HTTP headers & meta banners..."):
                tech_data = recon_engine.fingerprint_tech_stack(target["target_url"])
                st.json(tech_data)

        st.divider()
        st.subheader("🌐 Live Threat & Vulnerability Intelligence (CVE / EPSS)")
        st.caption("Query live NVD vulnerability records and EPSS exploitability probabilities for technology banners.")

        tech_keyword = st.text_input("Enter Tech Banner or Keyword for CVE Lookup", value="nginx 1.18.0")

        if st.button("Query NVD & EPSS Threat Intelligence"):
            with st.spinner(f"Fetching live CVE & EPSS intelligence for '{tech_keyword}'..."):
                cve_data = vuln_intel.search_cves_by_keyword(tech_keyword)
                if cve_data and "error" not in cve_data[0]:
                    st.success(f"Retrieved {len(cve_data)} threat intelligence records.")
                    st.dataframe(cve_data, use_container_width=True)
                else:
                    st.warning(cve_data[0].get("error", "No CVE records found."))

# -----------------------------------------------------------------------------
# PAGE 2: TARGET SCOPE CONTROL
# -----------------------------------------------------------------------------
elif nav_choice == "Target Scope Control":
    st.title("🎯 Target Scope Management")
    st.caption("Register target URLs within authorized testing boundaries.")

    with st.form("register_target_form"):
        label = st.text_input("Target Asset Label", value="Local OWASP Juice Shop")
        target_url = st.text_input("Target URL", value="http://localhost:3000")
        env_type = st.selectbox("Environment Type", ["Local Isolated Lab", "Staging Environment", "Containerized Service"])
        submit_target = st.form_submit_button("Authorize & Save Target")

        if submit_target:
            is_valid, message = validator.validate_target(target_url)
            if not is_valid:
                st.error(f"Target Registration Blocked: {message}")
            else:
                success = db.add_target(label, target_url, env_type)
                if success:
                    st.success(f"Target asset '{label}' successfully authorized!")
                else:
                    st.warning("Target URL already registered in database.")

    st.subheader("Currently Authorized Targets")
    st.table(db.fetch_all_targets())

# -----------------------------------------------------------------------------
# PAGE 3: RUN ASSESSMENT (MULTI-TARGET BATCH SCANNING)
# -----------------------------------------------------------------------------
elif nav_choice == "Run Assessment":
    st.title("🚀 Execute Assessment Run")
    st.caption("Launch security inspection runs across single or multiple authorized target assets.")
    
    targets = db.fetch_all_targets()
    if not targets:
        st.warning("No authorized target assets available. Please register a target in Scope Control first.")
    else:
        target_options = {f"{t['label']} ({t['target_url']})": t for t in targets}
        
        selected_keys = st.multiselect(
            "Select Target Assets for Assessment",
            options=list(target_options.keys()),
            default=[list(target_options.keys())[0]] if target_options else []
        )

        scan_profile = st.selectbox(
            "Select Inspection Profile",
            ["Custom HTTP Inspector", "Comprehensive Baseline Scan"]
        )

        if st.button("Launch Security Inspection Batch", type="primary"):
            if not selected_keys:
                st.warning("Please select at least one target asset to inspect.")
            else:
                st.info(f"Initiating batch assessment across {len(selected_keys)} target(s)...")
                
                total_new = 0
                total_dup = 0
                batch_summary = []

                progress_bar = st.progress(0)
                status_text = st.empty()

                for index, key in enumerate(selected_keys):
                    target = target_options[key]
                    status_text.text(f"Evaluating target [{index + 1}/{len(selected_keys)}]: {target['label']} ({target['target_url']})...")

                    is_valid, msg = validator.validate_target(target["target_url"])
                    if not is_valid:
                        st.error(f"Skipped {target['label']}: Scope Violation - {msg}")
                        batch_summary.append({
                            "Target": target["label"],
                            "URL": target["target_url"],
                            "Status": "Aborted (Scope Violation)",
                            "New Findings": 0,
                            "Duplicates": 0
                        })
                        continue

                    run_id = db.create_scan_run(target["id"], scan_profile)
                    results = inspector.run_checks(target["id"], target["target_url"])

                    new_count = 0
                    dup_count = 0

                    for item in results:
                        _, is_new = db.save_vulnerability(run_id, target["id"], item)
                        if is_new:
                            new_count += 1
                        else:
                            dup_count += 1

                    db.finalize_scan_run(run_id, "Completed")
                    
                    total_new += new_count
                    total_dup += dup_count

                    batch_summary.append({
                        "Target": target["label"],
                        "URL": target["target_url"],
                        "Run ID": f"#{run_id}",
                        "Status": "Completed",
                        "New Findings": new_count,
                        "Duplicates": dup_count
                    })

                    progress_bar.progress((index + 1) / len(selected_keys))

                status_text.empty()
                progress_bar.empty()

                st.success(f"Batch Execution Finished! Processed {len(selected_keys)} target(s) — Total New Findings: {total_new} | Total Duplicates Filtered: {total_dup}")
                st.subheader("Batch Execution Summary")
                st.dataframe(batch_summary, use_container_width=True)

# -----------------------------------------------------------------------------
# PAGE 4: ANALYST TRIAGING
# -----------------------------------------------------------------------------
elif nav_choice == "Analyst Triaging":
    st.title("🔎 Vulnerability Triaging & Validation")
    st.caption("Review scanner observations, attach technical notes, and confirm finding validity.")

    findings = db.fetch_vulnerabilities_overview()
    if not findings:
        st.info("No recorded findings available for triaging.")
    else:
        vuln_map = {f"#{f['id']} - {f['vuln_name']} [{f['review_state']}]": f for f in findings}
        selected_key = st.selectbox("Select Finding to Review", list(vuln_map.keys()))
        f_data = vuln_map[selected_key]

        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Finding ID:** {f_data['id']}")
            st.markdown(f"**Title:** {f_data['vuln_name']}")
            st.markdown(f"**Category:** {f_data['category']}")
            st.markdown(f"**Risk Level:** {f_data['risk_level']}")
            st.markdown(f"**Endpoint:** `{f_data['target_endpoint']}`")
            st.markdown(f"**Current Status:** `{f_data['review_state']}`")
        with col2:
            st.subheader("Captured Evidence")
            st.code(f_data['raw_observation'] or "No raw evidence recorded.", language="text")

        st.subheader("Remediation Guidance")
        st.info(f_data['remediation_guide'] or "No remediation guidance specified.")

        with st.form("triage_form"):
            new_state = st.selectbox("Validation Status", ["Unverified", "Confirmed Vulnerability", "False Positive", "Needs Manual Testing"])
            notes = st.text_area("Analyst Review Notes / Rationale", value=f_data['analyst_notes'] or "")
            save_review = st.form_submit_button("Save Validation Record")

            if save_review:
                db.update_review_state(f_data['id'], new_state, notes)
                st.success(f"Finding #{f_data['id']} review status updated to: {new_state}")
                st.rerun()

# -----------------------------------------------------------------------------
# PAGE 5: REMEDIATION RETEST
# -----------------------------------------------------------------------------
elif nav_choice == "Remediation Retest":
    st.title("🔄 Remediation Retest Audit")
    st.caption("Re-evaluate endpoints to verify whether issues have been successfully patched.")

    findings = db.fetch_vulnerabilities_overview()
    if not findings:
        st.info("No findings recorded for retesting.")
    else:
        vuln_map = {f"#{f['id']} - {f['vuln_name']} ({f['target_endpoint']})": f for f in findings}
        selected_key = st.selectbox("Select Finding to Retest", list(vuln_map.keys()))
        f_data = vuln_map[selected_key]

        if st.button("Execute Verification Retest"):
            st.info(f"Re-evaluating target endpoint: {f_data['target_endpoint']}...")
            fresh_results = inspector.run_checks(f_data['target_id'], f_data['target_endpoint'])
            
            still_present = any(item["name"] == f_data["vuln_name"] for item in fresh_results)

            if still_present:
                res_status = "Still Present"
                res_notes = f"Retest executed against {f_data['target_endpoint']}. Issue '{f_data['vuln_name']}' was still observed."
                st.warning(f"Retest Complete: Finding #{f_data['id']} is STILL PRESENT!")
            else:
                res_status = "Fixed"
                res_notes = f"Retest executed against {f_data['target_endpoint']}. Issue '{f_data['vuln_name']}' is no longer present."
                st.success(f"Retest Complete: Finding #{f_data['id']} is FIXED!")

            db.add_retest_record(f_data['id'], res_status, res_notes)

        st.subheader("Retest Audit History Logs")
        st.dataframe(db.fetch_retest_history(), use_container_width=True)

# -----------------------------------------------------------------------------
# PAGE 6: EXPORT REPORTS
# -----------------------------------------------------------------------------
elif nav_choice == "Export PDF Reports":
    st.header("📄 Export Security Assessment Reports")
    st.caption("Compile assessment results into PDF, SARIF v2.1.0, or JSON formats.")

    from reporting.sarif_exporter import SARIFExporter
    sarif_exp = SARIFExporter(db)

    targets = db.fetch_all_targets()
    if not targets:
        st.info("No targets or scan runs found.")
    else:
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.id, t.label, r.profile_name, r.execution_status, r.launched_at
            FROM scan_runs r
            JOIN targets t ON r.target_id = t.id
            ORDER BY r.id DESC
        """)
        runs = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not runs:
            st.info("No scan runs recorded yet.")
        else:
            run_dict = {f"Run #{r['id']} - {r['label']} ({r['profile_name']}) [{r['execution_status']}]": r['id'] for r in runs}
            selected_run_key = st.selectbox("Select Scan Run", list(run_dict.keys()))
            selected_run_id = run_dict[selected_run_key]

            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button("Compile PDF Report", use_container_width=True):
                    pdf_filename = f"VulnForge_Report_Run_{selected_run_id}.pdf"
                    path = pdf_gen.generate_report(selected_run_id, pdf_filename)
                    with open(path, "rb") as f:
                        st.download_button("Download PDF", f.read(), file_name=pdf_filename, mime="application/pdf")

            with col2:
                if st.button("Export SARIF (GitHub/SIEM)", use_container_width=True):
                    sarif_filename = f"VulnForge_Run_{selected_run_id}.sarif"
                    path = sarif_exp.export_run_to_sarif(selected_run_id, sarif_filename)
                    with open(path, "rb") as f:
                        st.download_button("Download SARIF", f.read(), file_name=sarif_filename, mime="application/json")

            with col3:
                if st.button("Export Structured JSON", use_container_width=True):
                    json_filename = f"VulnForge_Run_{selected_run_id}.json"
                    path = sarif_exp.export_run_to_json(selected_run_id, json_filename)
                    with open(path, "rb") as f:
                        st.download_button("Download JSON", f.read(), file_name=json_filename, mime="application/json")