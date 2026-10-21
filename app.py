import os
import streamlit as st
import pandas as pd
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector
from reporting.pdf_generator import PDFReportGenerator
from core.auth import AuthManager
from core.recon import ReconEngine
from engine.cve_lookup import VulnerabilityIntelligence

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="VulnForge VAPT Engine",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom High-End Cyber Operations Dashboard Styles
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background-color: #0b0e14;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #11151c;
        border-right: 1px solid #1f242d;
    }

    /* Metric Cards Grid */
    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        position: relative;
        overflow: hidden;
    }
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; width: 100%; height: 3px;
        background: linear-gradient(90deg, #388bfd, #1f6beb);
    }
    .metric-title {
        color: #8b949e;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
    }
    .metric-value {
        color: #f0f6fc;
        font-size: 2.2rem;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
    }

    /* Header Banner */
    .header-box {
        background: linear-gradient(90deg, #161b22 0%, #0f141c 100%);
        border: 1px solid #21262d;
        border-left: 4px solid #388bfd;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 24px;
    }
    .header-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #f0f6fc;
        margin: 0;
    }
    .header-subtitle {
        color: #8b949e;
        font-size: 0.85rem;
        margin-top: 4px;
    }

    /* Empty State Alert Box */
    .empty-state {
        background: #161b22;
        border: 1px dashed #30363d;
        border-radius: 8px;
        padding: 32px;
        text-align: center;
        color: #8b949e;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Core Services
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
# LOGIN GATEWAY
# -----------------------------------------------------------------------------
def render_login_screen():
    st.markdown("""
        <div style="text-align: center; margin-top: 40px; margin-bottom: 20px;">
            <h1 style="font-size: 2.5rem; font-weight: 800; color: #f0f6fc;">🛡️ V U L N F O R G E</h1>
            <p style="color: #8b949e; font-size: 1rem;">Enterprise Vulnerability Assessment & Automated Recon Engine</p>
        </div>
    """, unsafe_allow_html=True)

    _, col2, _ = st.columns([1, 1.1, 1])
    with col2:
        tab_login, tab_register = st.tabs(["🔐 Sign In", "👤 Register"])

        with tab_login:
            st.markdown("<br>", unsafe_allow_html=True)
            login_username = st.text_input("Username", key="login_user")
            login_password = st.text_input("Password", type="password", key="login_pass")

            if st.button("Log In to Console", use_container_width=True, type="primary"):
                if login_username and login_password:
                    user = auth_mgr.authenticate_user(login_username, login_password)
                    if user:
                        st.session_state["authenticated"] = True
                        st.session_state["user_info"] = user
                        st.rerun()
                    else:
                        st.error("Authentication failed. Invalid username or password.")

        with tab_register:
            st.markdown("<br>", unsafe_allow_html=True)
            reg_username = st.text_input("New Username", key="reg_user")
            reg_password = st.text_input("New Password", type="password", key="reg_pass")
            reg_role = st.selectbox("Role Assignment", ["Admin", "Analyst", "Viewer"], key="reg_role")

            if st.button("Create Operator Account", use_container_width=True):
                if reg_username and reg_password:
                    if auth_mgr.register_user(reg_username, reg_password, reg_role):
                        st.success(f"Account '{reg_username}' registered! You can now log in.")
                    else:
                        st.error("Username already registered.")

if not st.session_state["authenticated"]:
    render_login_screen()
    st.stop()

# -----------------------------------------------------------------------------
# SIDEBAR
# -----------------------------------------------------------------------------
current_user = st.session_state["user_info"]

st.sidebar.markdown("### 🛡️ VulnForge Core")
st.sidebar.markdown(f"**Operator:** `{current_user['username']}`")
st.sidebar.markdown(f"**Privilege:** `{current_user['role']}`")

if st.sidebar.button("Sign Out", use_container_width=True):
    st.session_state["authenticated"] = False
    st.session_state["user_info"] = None
    st.rerun()

st.sidebar.divider()

available_pages = ["Overview Dashboard", "Export Reports"]
if current_user["role"] in ["Admin", "Analyst"]:
    available_pages.insert(1, "Asset Reconnaissance")
    available_pages.insert(2, "Target Scope Control")
    available_pages.insert(3, "Run Assessment")
    available_pages.insert(4, "Analyst Triaging")
    available_pages.insert(5, "Remediation Retest")

nav_choice = st.sidebar.radio("Console Workspace", available_pages)

# -----------------------------------------------------------------------------
# WORKSPACE 1: OVERVIEW DASHBOARD
# -----------------------------------------------------------------------------
if nav_choice == "Overview Dashboard":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">📊 Security Operations Overview</div>
            <div class="header-subtitle">Real-time vulnerability metrics, asset status, and triage tracking</div>
        </div>
    """, unsafe_allow_html=True)
    
    targets = db.fetch_all_targets()
    findings = db.fetch_vulnerabilities_overview()
    
    unverified = sum(1 for f in findings if f["review_state"] == "Unverified")
    confirmed = sum(1 for f in findings if f["review_state"] == "Confirmed Vulnerability")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Registered Targets</div>
                <div class="metric-value">{len(targets)}</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Total Findings</div>
                <div class="metric-value">{len(findings)}</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Unverified Issues</div>
                <div class="metric-value" style="color: #d29922;">{unverified}</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Confirmed Issues</div>
                <div class="metric-value" style="color: #f85149;">{confirmed}</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if findings:
        df_findings = pd.DataFrame(findings)
        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("#### ⚠️ Severity Profile")
            severity_counts = df_findings["risk_level"].value_counts().reset_index()
            severity_counts.columns = ["Risk Level", "Count"]
            st.bar_chart(severity_counts, x="Risk Level", y="Count", color="#388bfd")

        with col_right:
            st.markdown("#### 📋 Triage Status")
            triage_counts = df_findings["review_state"].value_counts().reset_index()
            triage_counts.columns = ["Review State", "Count"]
            st.bar_chart(triage_counts, x="Review State", y="Count", color="#2ea043")

        st.divider()
        st.markdown("#### Discovered Vulnerability Log")
        st.dataframe(findings, use_container_width=True)
    else:
        st.markdown("""
            <div class="empty-state">
                <h4>No Vulnerabilities Recorded</h4>
                <p>Run an automated security assessment under <b>Run Assessment</b> to inspect targets.</p>
            </div>
        """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# WORKSPACE 2: ASSET RECONNAISSANCE
# -----------------------------------------------------------------------------
elif nav_choice == "Asset Reconnaissance":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">🔎 Automated Reconnaissance & Threat Intel</div>
            <div class="header-subtitle">CT log enumeration, async port scanning, banner fingerprinting, and NVD/EPSS intelligence</div>
        </div>
    """, unsafe_allow_html=True)

    targets = db.fetch_all_targets()
    if not targets:
        st.warning("No targets available. Please add targets under Target Scope Control.")
    else:
        target_map = {f"{t['label']} ({t['target_url']})": t for t in targets}
        selected_key = st.selectbox("Select Target Asset", list(target_map.keys()))
        target = target_map[selected_key]

        tab_recon, tab_intel = st.tabs(["⚡ Active & Passive Recon", "🌐 Threat & CVE Intelligence"])

        with tab_recon:
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 🌐 Subdomain Discovery")
                if st.button("Enumerate Subdomains", use_container_width=True):
                    with st.spinner("Querying CT logs..."):
                        subs = recon_engine.discover_subdomains(target["target_url"])
                        st.success(f"Discovered {len(subs)} subdomains.")
                        st.write(subs)

            with col2:
                st.markdown("#### 🔌 Async TCP Port Scan")
                if st.button("Scan TCP Ports", use_container_width=True):
                    with st.spinner("Scanning common ports..."):
                        open_ports = recon_engine.run_port_scan(target["target_url"])
                        if open_ports:
                            st.table(open_ports)
                        else:
                            st.info("No common open ports detected.")

            st.divider()
            st.markdown("#### 🧩 Web Tech Stack Fingerprinting")
            if st.button("Fingerprint Tech Stack", use_container_width=True):
                with st.spinner("Analyzing HTTP header banners..."):
                    st.json(recon_engine.fingerprint_tech_stack(target["target_url"]))

        with tab_intel:
            st.markdown("#### 🌐 NVD CVE & EPSS Intelligence")
            tech_keyword = st.text_input("Banner / Tech Keyword", value="nginx 1.18.0")

            if st.button("Search Threat Intelligence", use_container_width=True):
                with st.spinner(f"Querying NVD and EPSS database for '{tech_keyword}'..."):
                    cve_data = vuln_intel.search_cves_by_keyword(tech_keyword)
                    if not cve_data:
                        st.warning("No CVE records found.")
                    elif "error" in cve_data[0]:
                        st.error(cve_data[0]["error"])
                    else:
                        st.dataframe(cve_data, use_container_width=True)

# -----------------------------------------------------------------------------
# WORKSPACE 3: TARGET SCOPE CONTROL
# -----------------------------------------------------------------------------
elif nav_choice == "Target Scope Control":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">🎯 Target Scope Management</div>
            <div class="header-subtitle">Authorize target domains and define security testing boundaries</div>
        </div>
    """, unsafe_allow_html=True)

    with st.form("register_target_form"):
        st.markdown("#### Authorize New Target Asset")
        label = st.text_input("Asset Label", value="Juice Shop Test Environment")
        target_url = st.text_input("Target URL", value="http://localhost:3000")
        env_type = st.selectbox("Environment", ["Local Isolated Lab", "Staging Environment", "Containerized Service"])
        
        if st.form_submit_button("Authorize Asset", type="primary"):
            is_valid, message = validator.validate_target(target_url)
            if not is_valid:
                st.error(f"Scope Violation: {message}")
            else:
                if db.add_target(label, target_url, env_type):
                    st.success(f"Successfully authorized asset: '{label}'")
                else:
                    st.warning("Target URL is already registered.")

    st.divider()
    st.markdown("#### Authorized Assets")
    st.table(db.fetch_all_targets())

# -----------------------------------------------------------------------------
# WORKSPACE 4: RUN ASSESSMENT
# -----------------------------------------------------------------------------
elif nav_choice == "Run Assessment":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">🚀 Assessment Execution Pipeline</div>
            <div class="header-subtitle">Run automated security inspection runs across authorized target scopes</div>
        </div>
    """, unsafe_allow_html=True)

    targets = db.fetch_all_targets()
    if not targets:
        st.warning("No targets authorized. Add target scope first.")
    else:
        target_options = {f"{t['label']} ({t['target_url']})": t for t in targets}
        selected_keys = st.multiselect("Select Target Assets", options=list(target_options.keys()))
        scan_profile = st.selectbox("Inspection Profile", ["Custom HTTP Inspector", "Comprehensive Baseline Scan"])

        if st.button("Launch Batch Security Run", type="primary", use_container_width=True):
            if not selected_keys:
                st.warning("Please select at least one target.")
            else:
                progress_bar = st.progress(0)
                batch_summary = []

                with st.status("Executing Assessment Run...", expanded=True) as status_container:
                    for idx, key in enumerate(selected_keys):
                        target = target_options[key]
                        st.write(f"🔍 **Evaluating Target:** `{target['label']}` ({target['target_url']})")

                        is_valid, msg = validator.validate_target(target["target_url"])
                        if not is_valid:
                            st.write(f"❌ **Scope Violation:** {msg}")
                            continue

                        run_id = db.create_scan_run(target["id"], scan_profile)
                        results = inspector.run_checks(target["id"], target["target_url"])

                        new_count = 0
                        dup_count = 0
                        for item in results:
                            _, is_new = db.save_vulnerability(run_id, target["id"], item)
                            if is_new:
                                new_count += 1
                                st.write(f"  └ ⚠️ Discovered: `{item['name']}` [{item['risk_level']}]")
                            else:
                                dup_count += 1

                        db.finalize_scan_run(run_id, "Completed")
                        batch_summary.append({
                            "Target": target["label"],
                            "Run ID": f"#{run_id}",
                            "New Findings": new_count,
                            "Duplicates Filtered": dup_count
                        })
                        progress_bar.progress((idx + 1) / len(selected_keys))

                    status_container.update(label="Assessment Complete!", state="complete", expanded=False)

                st.markdown("#### Execution Summary")
                st.dataframe(batch_summary, use_container_width=True)

# -----------------------------------------------------------------------------
# WORKSPACE 5: ANALYST TRIAGING
# -----------------------------------------------------------------------------
elif nav_choice == "Analyst Triaging":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">🔎 Vulnerability Triaging & Review</div>
            <div class="header-subtitle">Evaluate findings, document rationale, and confirm vulnerability states</div>
        </div>
    """, unsafe_allow_html=True)

    findings = db.fetch_vulnerabilities_overview()
    if not findings:
        st.info("No findings available for triaging.")
    else:
        vuln_map = {f"#{f['id']} - {f['vuln_name']} [{f['review_state']}]": f for f in findings}
        selected_key = st.selectbox("Select Finding for Review", list(vuln_map.keys()))
        f_data = vuln_map[selected_key]

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Finding ID:** `{f_data['id']}`")
            st.markdown(f"**Title:** {f_data['vuln_name']}")
            st.markdown(f"**Severity:** `{f_data['risk_level']}`")
            st.markdown(f"**Current Status:** `{f_data['review_state']}`")
        with col2:
            st.markdown("**Evidence Snapshot:**")
            st.code(f_data['raw_observation'] or "No raw evidence.", language="text")

        with st.form("triage_form"):
            new_state = st.selectbox("Validation Status", ["Unverified", "Confirmed Vulnerability", "False Positive", "Needs Manual Testing"])
            notes = st.text_area("Analyst Rationale / Notes", value=f_data['analyst_notes'] or "")
            if st.form_submit_button("Update Finding Status", type="primary"):
                db.update_review_state(f_data['id'], new_state, notes)
                st.success(f"Status updated to: {new_state}")
                st.rerun()

# -----------------------------------------------------------------------------
# WORKSPACE 6: REMEDIATION RETEST
# -----------------------------------------------------------------------------
elif nav_choice == "Remediation Retest":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">🔄 Remediation Verification Retest</div>
            <div class="header-subtitle">Re-evaluate patched target endpoints and maintain audit records</div>
        </div>
    """, unsafe_allow_html=True)

    findings = db.fetch_vulnerabilities_overview()
    if not findings:
        st.info("No recorded findings for retesting.")
    else:
        vuln_map = {f"#{f['id']} - {f['vuln_name']} ({f['target_endpoint']})": f for f in findings}
        selected_key = st.selectbox("Select Finding to Retest", list(vuln_map.keys()))
        f_data = vuln_map[selected_key]

        if st.button("Execute Endpoint Retest", type="primary"):
            fresh_results = inspector.run_checks(f_data['target_id'], f_data['target_endpoint'])
            still_present = any(item["name"] == f_data["vuln_name"] for item in fresh_results)
            
            res_status = "Still Present" if still_present else "Fixed"
            db.add_retest_record(f_data['id'], res_status, f"Retest against {f_data['target_endpoint']} resulted in: {res_status}")

            if still_present:
                st.warning("Retest Result: Vulnerability is STILL PRESENT.")
            else:
                st.success("Retest Result: Vulnerability is FIXED.")

        st.divider()
        st.markdown("#### Retest Audit History Log")
        st.dataframe(db.fetch_retest_history(), use_container_width=True)

# -----------------------------------------------------------------------------
# WORKSPACE 7: EXPORT REPORTS
# -----------------------------------------------------------------------------
elif nav_choice == "Export Reports":
    st.markdown("""
        <div class="header-box">
            <div class="header-title">📄 Security Assessment Reports</div>
            <div class="header-subtitle">Generate executive PDF reports, GitHub-compliant SARIF v2.1.0, or JSON records</div>
        </div>
    """, unsafe_allow_html=True)

    from reporting.sarif_exporter import SARIFExporter
    sarif_exp = SARIFExporter(db)

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
        run_dict = {f"Run #{r['id']} - {r['label']} ({r['profile_name']})": r['id'] for r in runs}
        selected_run_id = run_dict[st.selectbox("Select Scan Run", list(run_dict.keys()))]

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Generate Executive PDF", use_container_width=True):
                path = pdf_gen.generate_report(selected_run_id, f"VulnForge_Run_{selected_run_id}.pdf")
                with open(path, "rb") as f:
                    st.download_button("Download PDF", f.read(), file_name=os.path.basename(path), mime="application/pdf", use_container_width=True)

        with col2:
            if st.button("Export SARIF v2.1.0", use_container_width=True):
                path = sarif_exp.export_run_to_sarif(selected_run_id, f"VulnForge_Run_{selected_run_id}.sarif")
                with open(path, "rb") as f:
                    st.download_button("Download SARIF", f.read(), file_name=os.path.basename(path), mime="application/json", use_container_width=True)

        with col3:
            if st.button("Export Structured JSON", use_container_width=True):
                path = sarif_exp.export_run_to_json(selected_run_id, f"VulnForge_Run_{selected_run_id}.json")
                with open(path, "rb") as f:
                    st.download_button("Download JSON", f.read(), file_name=os.path.basename(path), mime="application/json", use_container_width=True)