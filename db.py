import sqlite3
from typing import List, Dict, Any, Optional

class DatabaseManager:
    """Encapsulates all relational database logic for the VulnForge platform."""

    def __init__(self, db_file: str = "vulnforge_app.db"):
        self.db_file = db_file
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row  # Access columns by dictionary key
        return conn

    def _init_tables(self) -> None:
        """Initializes tables for targets, assessment runs, findings, evidence, and retests."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Registered Target Assets
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                target_url TEXT NOT NULL UNIQUE,
                environment TEXT NOT NULL,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # 2. Assessment Runs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                execution_status TEXT NOT NULL,
                profile_name TEXT NOT NULL,
                launched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """)

            # 3. Discovered Vulnerabilities
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                vuln_name TEXT NOT NULL,
                category TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                confidence_score TEXT NOT NULL,
                review_state TEXT DEFAULT 'Unverified',
                target_endpoint TEXT NOT NULL,
                remediation_guide TEXT,
                analyst_notes TEXT,
                fingerprint TEXT UNIQUE,
                FOREIGN KEY (run_id) REFERENCES scan_runs (id),
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """)

            # 4. Evidence Logs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER NOT NULL,
                check_source TEXT NOT NULL,
                raw_observation TEXT NOT NULL,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id)
            )
            """)

            # 5. Remediation Retest Logs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS retest_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER NOT NULL,
                retest_result TEXT NOT NULL,
                retest_notes TEXT NOT NULL,
                performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id)
            )
            """)
            conn.commit()

    # --- Target Management ---
    def add_target(self, label: str, target_url: str, environment: str) -> bool:
        with self._get_connection() as conn:
            try:
                conn.cursor().execute(
                    "INSERT INTO targets (label, target_url, environment) VALUES (?, ?, ?)",
                    (label, target_url, environment)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def fetch_all_targets(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    # --- Scan Run Management ---
    def create_scan_run(self, target_id: int, profile_name: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_runs (target_id, execution_status, profile_name) VALUES (?, ?, ?)",
                (target_id, "Running", profile_name)
            )
            conn.commit()
            return cursor.lastrowid

    def save_vulnerability(self, run_id: int, target_id: int, vuln: Dict[str, Any]) -> tuple[Optional[int], bool]:
        """Saves vulnerability and evidence. Uses unique fingerprint to enforce deduplication."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO vulnerabilities (run_id, target_id, vuln_name, category, risk_level, confidence_score, target_endpoint, remediation_guide, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id, target_id, vuln["name"], vuln["category"], vuln["risk_level"],
                    vuln["confidence"], vuln["endpoint"], vuln["remediation"], vuln["fingerprint"]
                ))
                vuln_id = cursor.lastrowid
                
                cursor.execute("""
                    INSERT INTO evidence_logs (vuln_id, check_source, raw_observation)
                    VALUES (?, ?, ?)
                """, (vuln_id, vuln["check_source"], vuln["evidence"]))
                
                conn.commit()
                return vuln_id, True
            except sqlite3.IntegrityError:
                return None, False

    def finalize_scan_run(self, run_id: int, status: str = "Completed") -> None:
        with self._get_connection() as conn:
            conn.cursor().execute(
                "UPDATE scan_runs SET execution_status = ?, ended_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, run_id)
            )
            conn.commit()

    # --- Triaging & Validation ---
    def fetch_vulnerabilities_overview(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.id, v.run_id, v.target_id, v.vuln_name, v.category, v.risk_level, 
                       v.confidence_score, v.review_state, v.target_endpoint, v.remediation_guide, 
                       v.analyst_notes, e.raw_observation, t.label as target_label
                FROM vulnerabilities v
                LEFT JOIN evidence_logs e ON v.id = e.vuln_id
                LEFT JOIN targets t ON v.target_id = t.id
                ORDER BY v.id DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def update_review_state(self, vuln_id: int, new_state: str, notes: str) -> None:
        with self._get_connection() as conn:
            conn.cursor().execute(
                "UPDATE vulnerabilities SET review_state = ?, analyst_notes = ? WHERE id = ?",
                (new_state, notes, vuln_id)
            )
            conn.commit()

    # --- Retest Audit ---
    def add_retest_record(self, vuln_id: int, result: str, notes: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO retest_logs (vuln_id, retest_result, retest_notes) VALUES (?, ?, ?)",
                (vuln_id, result, notes)
            )
            if result == "Fixed":
                cursor.execute("UPDATE vulnerabilities SET review_state = 'Resolved' WHERE id = ?", (vuln_id,))
            elif result == "Still Present":
                cursor.execute("UPDATE vulnerabilities SET review_state = 'Confirmed Vulnerability' WHERE id = ?", (vuln_id,))
            conn.commit()

    def fetch_retest_history(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.id, r.vuln_id, v.vuln_name, r.retest_result, r.retest_notes, r.performed_at
                FROM retest_logs r
                JOIN vulnerabilities v ON r.vuln_id = v.id
                ORDER BY r.id DESC
            """)
            return [dict(row) for row in cursor.fetchall()]