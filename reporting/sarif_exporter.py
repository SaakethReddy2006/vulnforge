import json
import os
from typing import Dict, Any, List
from db import DatabaseManager

class SARIFExporter:
    """Exports VulnForge findings into standardized SARIF v2.1.0 and JSON formats."""

    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager or DatabaseManager()

    def _map_risk_to_sarif_level(self, risk_level: str) -> str:
        risk_map = {
            "Critical": "error",
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Info": "note"
        }
        return risk_map.get(risk_level, "warning")

    def export_run_to_sarif(self, run_id: int, output_filepath: str = None) -> str:
        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, profile_name, launched_at FROM scan_runs WHERE id = ?", (run_id,))
        run_row = cursor.fetchone()
        if not run_row:
            conn.close()
            raise ValueError(f"Scan run #{run_id} not found.")

        # Fixed column names: run_id and confidence_score
        cursor.execute("""
            SELECT id, vuln_name, category, risk_level, confidence_score, 
                   target_endpoint, remediation_guide, fingerprint
            FROM vulnerabilities
            WHERE run_id = ?
        """, (run_id,))
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()

        rules = []
        results = []
        rule_indices = {}

        for finding in findings:
            rule_id = f"VF-{finding['category'].replace(' ', '-').upper()}"
            
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": finding["vuln_name"],
                    "shortDescription": {"text": finding["vuln_name"]},
                    "fullDescription": {"text": f"Category: {finding['category']}. Confidence: {finding['confidence_score']}."},
                    "help": {"text": finding["remediation_guide"] or "No remediation guide specified."},
                    "properties": {"tags": [finding["category"], f"Risk:{finding['risk_level']}"]}
                })

            level = self._map_risk_to_sarif_level(finding["risk_level"])
            
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": level,
                "message": {"text": f"{finding['vuln_name']} observed at {finding['target_endpoint']}."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["target_endpoint"]}
                    }
                }],
                "partialFingerprints": {
                    "primaryLogicalFingerprint": finding["fingerprint"]
                }
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnForge VAPT Platform",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/SaakethReddy2006/vulnforge",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

        filename = output_filepath or f"vulnforge_run_{run_id}.sarif"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)

        return filename

    def export_run_to_json(self, run_id: int, output_filepath: str = None) -> str:
        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,))
        run_data = cursor.fetchone()
        if not run_data:
            conn.close()
            raise ValueError(f"Scan run #{run_id} not found.")

        cursor.execute("SELECT * FROM vulnerabilities WHERE run_id = ?", (run_id,))
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()

        export_payload = {
            "platform": "VulnForge",
            "scan_run": dict(run_data),
            "findings_count": len(findings),
            "findings": findings
        }

        filename = output_filepath or f"vulnforge_run_{run_id}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_payload, f, indent=2)

        return filename