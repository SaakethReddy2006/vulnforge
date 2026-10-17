import os
import streamlit as st
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector
from reporting.pdf_generator import PDFReportGenerator

# Initialize Core Services
db = DatabaseManager()
validator = ScopeValidator()
inspector = SecurityInspector()
pdf_gen = PDFReportGenerator()

st.set_page_config(page_title="VulnForge Portal", layout="wide", page_icon="🛡️")

# Navigation Sidebar
st.sidebar.title("🛡️ VulnForge Platform")
st.sidebar.caption("SecOps VAPT & Evidence Platform")

nav_choice = st.sidebar.radio("Navigation Menu", [
    "Overview Dashboard",
    "Target Scope Control",
    "Run Assessment",
    "Analyst Triaging",
    "Remediation Retest",
    "Export PDF Reports"
])

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
# PAGE 3: RUN ASSESSMENT
# -----------------------------------------------------------------------------
elif nav_choice == "Run Assessment":
    st.title("🚀 Execute Assessment Run")
    
    targets = db.fetch_all_targets()
    if not targets:
        st.warning("No authorized target assets available. Please register a target first.")
    else:
        target_options = {f"{t['label']} ({t['target_url']})": t for t in targets}
        selected_key = st.selectbox("Select Target Asset", list(target_options.keys()))
        selected_target = target_options[selected_key]

        if st.button("Launch Security Inspection"):
            # Enforce Scope again prior to scanning
            is_valid, msg = validator.validate_target(selected_target["target_url"])
            if not is_valid:
                st.error(f"Scan Execution Aborted: {msg}")
            else:
                st.info(f"Executing checks against {selected_target['target_url']}...")
                
                run_id = db.create_scan_run(selected_target["id"], "Custom HTTP Inspector")
                results = inspector.run_checks(selected_target["id"], selected_target["target_url"])

                new_count = 0
                dup_count = 0

                for item in results:
                    _, is_new = db.save_vulnerability(run_id, selected_target["id"], item)
                    if is_new:
                        new_count += 1
                    else:
                        dup_count += 1

                db.finalize_scan_run(run_id, "Completed")
                st.success(f"Scan Run #{run_id} complete! Added {new_count} new observation(s). ({dup_count} duplicate(s) filtered)")
                
                if results:
                    st.dataframe(results, use_container_width=True)

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
# PAGE 6: EXPORT PDF REPORTS
# -----------------------------------------------------------------------------
elif nav_choice == "Export PDF Reports":
    st.header("📄 Export PDF Security Reports")
    st.caption("Compile assessment results, evidence snippets, and triaging rationale into publication-ready PDF reports.")

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
            st.info("No scan runs recorded yet. Execute an assessment run first.")
        else:
            run_dict = {f"Run #{r['id']} - {r['label']} ({r['profile_name']}) [{r['execution_status']}] - {r['launched_at']}": r['id'] for r in runs}
            selected_run_key = st.selectbox("Select Scan Run", list(run_dict.keys()))
            selected_run_id = run_dict[selected_run_key]

            if st.button("Compile Executive PDF Report"):
                try:
                    pdf_filename = f"VulnForge_Executive_Report_Run_{selected_run_id}.pdf"
                    generated_path = pdf_gen.generate_report(selected_run_id, pdf_filename)

                    st.success(f"Report compiled successfully: `{generated_path}`")

                    with open(generated_path, "rb") as file_bytes:
                        st.download_button(
                            label="Download PDF Report",
                            data=file_bytes.read(),
                            file_name=pdf_filename,
                            mime="application/pdf"
                        )
                except Exception as e:
                    st.error(f"Report Generation Failed: {str(e)}")