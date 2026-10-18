import argparse
import sys
import json
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector
from reporting.sarif_exporter import SARIFExporter

def main():
    parser = argparse.ArgumentParser(
        description="VulnForge Headless CLI & CI/CD Security Gate Scanner"
    )
    parser.add_argument("--target-url", required=True, help="Target URL to assess (e.g. http://localhost:3000)")
    parser.add_argument("--label", default="CI/CD Target Asset", help="Target asset label")
    parser.add_argument("--profile", default="CI/CD Pipeline Security Gate", help="Scan profile name")
    parser.add_argument("--fail-on", choices=["Critical", "High", "Medium", "Low"], default="High",
                        help="Severity threshold that triggers non-zero exit code (default: High)")
    parser.add_argument("--sarif-out", default="vulnforge_results.sarif", help="Path to write SARIF report")
    parser.add_argument("--json-out", default="vulnforge_results.json", help="Path to write JSON report")

    args = parser.parse_args()

    db = DatabaseManager()
    validator = ScopeValidator()
    inspector = SecurityInspector()
    exporter = SARIFExporter(db)

    print(f"[*] VulnForge Headless CLI Scanner starting...")
    print(f"[*] Target URL: {args.target_url}")
    print(f"[*] Severity Policy Gate: Fail on >= {args.fail_on}")

    # 1. Scope Validation Gate
    is_valid, msg = validator.validate_target(args.target_url)
    if not is_valid:
        print(f"[!] SCOPE VIOLATION ERROR: {msg}")
        sys.exit(2)

    # 2. Register Target & Initiate Run
    db.add_target(args.label, args.target_url, "CI/CD Pipeline Runner")
    targets = db.fetch_all_targets()
    target_id = next(t["id"] for t in targets if t["target_url"] == args.target_url)

    run_id = db.create_scan_run(target_id, args.profile)
    print(f"[*] Created Scan Run ID #{run_id}")

    # 3. Execute Security Inspection
    findings = inspector.run_checks(target_id, args.target_url)
    new_findings = 0
    duplicate_findings = 0

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for finding in findings:
        _, is_new = db.save_vulnerability(run_id, target_id, finding)
        if is_new:
            new_findings += 1
        else:
            duplicate_findings += 1
        
        risk = finding.get("risk_level", "Info")
        if risk in severity_counts:
            severity_counts[risk] += 1

    db.finalize_scan_run(run_id, "Completed")
    print(f"[+] Scan completed successfully.")
    print(f"    - Total Findings Detected: {len(findings)} (New: {new_findings}, Duplicates: {duplicate_findings})")
    print(f"    - Severity Distribution: {json.dumps(severity_counts)}")

    # 4. Generate Export Artifacts
    sarif_path = exporter.export_run_to_sarif(run_id, args.sarif_out)
    json_path = exporter.export_run_to_json(run_id, args.json_out)
    print(f"[+] Exported SARIF report: {sarif_path}")
    print(f"[+] Exported JSON report:  {json_path}")

    # 5. Evaluate CI/CD Security Gate Thresholds
    severity_order = ["Low", "Medium", "High", "Critical"]
    fail_index = severity_order.index(args.fail_on)

    failed_policy = False
    for risk_level, count in severity_counts.items():
        if risk_level in severity_order and count > 0:
            if severity_order.index(risk_level) >= fail_index:
                print(f"[!] SECURITY GATE FAILURE: Found {count} finding(s) with risk '{risk_level}' (Threshold: >= {args.fail_on})")
                failed_policy = True

    if failed_policy:
        print("[!] CI/CD Security Gate Check: FAILED")
        sys.exit(1)
    else:
        print("[+] CI/CD Security Gate Check: PASSED")
        sys.exit(0)

if __name__ == "__main__":
    main()