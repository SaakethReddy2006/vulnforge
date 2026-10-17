import os
import gc
import pytest
from db import DatabaseManager
from core.validator import ScopeValidator
from engine.custom_scanner import SecurityInspector

TEST_DB = "test_vulnforge.db"

@pytest.fixture
def db():
    """Sets up an isolated clean database instance for testing with Windows lock prevention."""
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass

    manager = DatabaseManager(db_file=TEST_DB)
    yield manager

    # Release memory garbage collection to drop lingering SQLite handles on Windows
    del manager
    gc.collect()

    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass

def test_scope_validator():
    """Verifies scope policy allows authorized hosts and blocks external domains."""
    validator = ScopeValidator(allowed_domains=["localhost", "127.0.0.1", "juiceshop.local"])
    
    # Authorized target hosts
    valid, _ = validator.validate_target("http://localhost:3000")
    assert valid is True

    valid, _ = validator.validate_target("https://juiceshop.local/login")
    assert valid is True

    # Out-of-scope external targets
    valid, msg = validator.validate_target("https://google.com")
    assert valid is False
    assert "Scope Violation" in msg

    # Malformed URL structures
    valid, msg = validator.validate_target("not_a_valid_url")
    assert valid is False

def test_database_target_and_runs(db):
    """Verifies target registration and scan run initialization."""
    success = db.add_target("Test Lab", "http://localhost:3000", "Local")
    assert success is True

    # Duplicate target URL registration should fail cleanly
    duplicate_success = db.add_target("Test Lab Duplicate", "http://localhost:3000", "Local")
    assert duplicate_success is False

    targets = db.fetch_all_targets()
    assert len(targets) == 1
    assert targets[0]["label"] == "Test Lab"

    run_id = db.create_scan_run(targets[0]["id"], "Test Profile")
    assert run_id > 0

def test_fingerprint_deduplication(db):
    """Verifies that unique SHA-256 fingerprints prevent duplicate findings."""
    db.add_target("Test Lab", "http://localhost:3000", "Local")
    targets = db.fetch_all_targets()
    target_id = targets[0]["id"]
    run_id = db.create_scan_run(target_id, "Test Profile")

    inspector = SecurityInspector()
    fingerprint = inspector._build_fingerprint(target_id, "http://localhost:3000", "Missing Header: CSP", "Evidence Snippet")

    finding_data = {
        "name": "Missing Security Header: Content-Security-Policy",
        "category": "HTTP Security Headers",
        "risk_level": "Medium",
        "confidence": "High",
        "endpoint": "http://localhost:3000",
        "remediation": "Add CSP Header",
        "evidence": "Evidence Snippet",
        "check_source": "Test Suite",
        "fingerprint": fingerprint
    }

    # First insertion should succeed
    vuln_id_1, is_new_1 = db.save_vulnerability(run_id, target_id, finding_data)
    assert vuln_id_1 is not None
    assert is_new_1 is True

    # Duplicate insertion with identical fingerprint should be skipped cleanly
    vuln_id_2, is_new_2 = db.save_vulnerability(run_id, target_id, finding_data)
    assert vuln_id_2 is None
    assert is_new_2 is False

    overview = db.fetch_vulnerabilities_overview()
    assert len(overview) == 1