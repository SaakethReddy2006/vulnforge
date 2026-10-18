import os
import json
import pytest
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector
from reporting.sarif_exporter import SARIFExporter
from core.recon import ReconEngine

@pytest.fixture
def test_db(tmp_path):
    """Fixture to provide a clean temporary database instance for isolated testing."""
    db_file = tmp_path / "test_vulnforge.db"
    return DatabaseManager(db_file=str(db_file))

def test_scope_validator_authorization():
    """Verify scope validator correctly approves local targets and rejects unauthorized egress URLs."""
    validator = ScopeValidator()
    
    # Authorized local lab target
    is_valid, _ = validator.validate_target("http://localhost:3000")
    assert is_valid is True

    # Unauthorized external egress target
    is_valid_ext, msg = validator.validate_target("https://google.com")
    assert is_valid_ext is False
    assert "Scope Violation" in msg or "Unauthorized" in msg

def test_target_registration_and_scan_run(test_db):
    """Verify target asset creation and scan run lifecycle in database DAO."""
    success = test_db.add_target("Test Local Target", "http://localhost:8000", "Local Isolated Lab")
    assert success is True

    targets = test_db.fetch_all_targets()
    assert len(targets) == 1
    target_id = targets[0]["id"]

    run_id = test_db.create_scan_run(target_id, "Test Profile")
    assert run_id is not None

    test_db.finalize_scan_run(run_id, "Completed")
    
    conn = test_db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT execution_status FROM scan_runs WHERE id = ?", (run_id,))
    status = cursor.fetchone()["execution_status"]
    conn.close()

    assert status == "Completed"

def test_vulnerability_fingerprint_deduplication(test_db):
    """Verify SHA-256 fingerprint deduplication prevents duplicate vulnerability entries."""
    test_db.add_target("Deduplication Target", "http://localhost:8080", "Local Isolated Lab")
    targets = test_db.fetch_all_targets()
    target_id = targets[0]["id"]
    run_id = test_db.create_scan_run(target_id, "Deduplication Profile")

    finding_item = {
        "name": "Missing Security Header: X-Frame-Options",
        "category": "HTTP Security Headers",
        "risk_level": "Low",
        "confidence": "High",
        "endpoint": "http://localhost:8080",
        "remediation": "Configure X-Frame-Options header.",
        "evidence": "Header missing.",
        "check_source": "SecurityInspector Engine",
        "fingerprint": "fixed_test_sha256_fingerprint_123"
    }

    # First insertion - should succeed as new
    vuln_id_1, is_new_1 = test_db.save_vulnerability(run_id, target_id, finding_item)
    assert is_new_1 is True
    assert vuln_id_1 is not None

    # Second insertion with same fingerprint - should correctly flag as duplicate
    _, is_new_2 = test_db.save_vulnerability(run_id, target_id, finding_item)
    assert is_new_2 is False

def test_sarif_and_json_exporter_integration(test_db, tmp_path):
    """Verify SARIF v2.1.0 and JSON export generation and structure."""
    test_db.add_target("SARIF Test Lab", "http://localhost:8000", "Local Isolated Lab")
    targets = test_db.fetch_all_targets()
    target_id = targets[0]["id"]

    run_id = test_db.create_scan_run(target_id, "Automated Inspector Test")

    finding_sample = {
        "name": "Missing Security Header: Content-Security-Policy",
        "category": "HTTP Security Headers",
        "risk_level": "Medium",
        "confidence": "High",
        "endpoint": "http://localhost:8000",
        "remediation": "Configure a strict Content-Security-Policy (CSP) header.",
        "evidence": "Header Content-Security-Policy was missing.",
        "check_source": "SecurityInspector Engine",
        "fingerprint": "mock_sarif_sha256_fingerprint_999"
    }
    test_db.save_vulnerability(run_id, target_id, finding_sample)
    test_db.finalize_scan_run(run_id, "Completed")

    exporter = SARIFExporter(db_manager=test_db)

    # 1. Test SARIF v2.1.0 Export
    sarif_file = str(tmp_path / "test_run.sarif")
    output_sarif_path = exporter.export_run_to_sarif(run_id, sarif_file)
    
    assert os.path.exists(output_sarif_path)
    with open(output_sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) == 1
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "VulnForge VAPT Platform"
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["level"] == "warning"

    # 2. Test Standard JSON Export
    json_file = str(tmp_path / "test_run.json")
    output_json_path = exporter.export_run_to_json(run_id, json_file)

    assert os.path.exists(output_json_path)
    with open(output_json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    assert json_data["platform"] == "VulnForge"
    assert json_data["findings_count"] == 1
    assert json_data["findings"][0]["vuln_name"] == "Missing Security Header: Content-Security-Policy"

def test_recon_engine_subdomain_discovery_scope_filter():
    """Verify ReconEngine returns only authorized target domain/subdomains based on ScopeValidator."""
    validator = ScopeValidator()
    recon = ReconEngine(validator=validator)

    # Authorized local domain
    subdomains = recon.discover_subdomains("localhost")
    assert isinstance(subdomains, list)
    assert "localhost" in subdomains

    # External unauthorized domain should return empty list due to zero-trust scope filter
    ext_subdomains = recon.discover_subdomains("example.com")
    assert ext_subdomains == []

def test_recon_engine_async_port_scan():
    """Verify async TCP port scanning returns structured list of port states."""
    validator = ScopeValidator()
    recon = ReconEngine(validator=validator)

    # Probe port 8