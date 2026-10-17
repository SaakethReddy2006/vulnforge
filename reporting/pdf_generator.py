import os
import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class PDFReportGenerator:
    """Generates professional executive PDF security assessment reports."""

    def __init__(self, db_path: str = "vulnforge_app.db"):
        self.db_path = db_path

    def generate_report(self, run_id: int, output_filename: Optional[str] = None) -> str:
        """Queries assessment findings and outputs a compiled PDF report."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Fetch Run and Target details
        cursor.execute("""
            SELECT r.id, r.execution_status, r.profile_name, r.launched_at, r.ended_at,
                   t.label, t.target_url, t.environment
            FROM scan_runs r
            JOIN targets t ON r.target_id = t.id
            WHERE r.id = ?
        """, (run_id,))
        run_data = cursor.fetchone()

        if not run_data:
            conn.close()
            raise ValueError(f"Scan Run #{run_id} not found in database.")

        # Fetch Findings for this target
        cursor.execute("""
            SELECT v.id, v.vuln_name, v.category, v.risk_level, v.confidence_score, 
                   v.review_state, v.target_endpoint, v.remediation_guide, v.analyst_notes, e.raw_observation
            FROM vulnerabilities v
            LEFT JOIN evidence_logs e ON v.id = e.vuln_id
            WHERE v.run_id = ?
            ORDER BY v.id ASC
        """, (run_id,))
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not output_filename:
            output_filename = f"VulnForge_Executive_Report_Run_{run_id}.pdf"

        # Initialize PDF Document
        doc = SimpleDocTemplate(
            output_filename, pagesize=letter,
            rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0F172A'))
        h2_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1E293B'), spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle('Body', parent=styles['BodyText'], fontSize=9, leading=12, textColor=colors.HexColor('#334155'))
        code_style = ParagraphStyle('CodeSnippet', parent=styles['Code'], fontSize=8, textColor=colors.HexColor('#0F172A'), backColor=colors.HexColor('#F1F5F9'), borderPadding=4)

        elements = []

        # Report Title Header
        elements.append(Paragraph("VulnForge Security Assessment Report", title_style))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", body_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=12))

        # Scope Summary Table
        elements.append(Paragraph("1. Assessment Overview & Target Scope", h2_style))
        scope_table_data = [
            [Paragraph("<b>Target Asset:</b>", body_style), Paragraph(run_data["label"], body_style),
             Paragraph("<b>Environment:</b>", body_style), Paragraph(run_data["environment"], body_style)],
            [Paragraph("<b>Target URL:</b>", body_style), Paragraph(run_data["target_url"], body_style),
             Paragraph("<b>Scan Profile:</b>", body_style), Paragraph(run_data["profile_name"], body_style)],
            [Paragraph("<b>Execution Status:</b>", body_style), Paragraph(run_data["execution_status"], body_style),
             Paragraph("<b>Run ID:</b>", body_style), Paragraph(f"#{run_data['id']}", body_style)]
        ]

        t_scope = Table(scope_table_data, colWidths=[100, 170, 100, 170])
        t_scope.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(t_scope)
        elements.append(Spacer(1, 10))

        # Findings Section
        elements.append(Paragraph(f"2. Discovered Findings ({len(findings)})", h2_style))

        if not findings:
            elements.append(Paragraph("No security observations recorded during this run.", body_style))
        else:
            for idx, item in enumerate(findings, start=1):
                # Severity Color Coding
                risk_str = item["risk_level"].upper()
                color_hex = "#64748B"
                if risk_str == "HIGH": color_hex = "#DC2626"
                elif risk_str == "MEDIUM": color_hex = "#D97706"
                elif risk_str == "LOW": color_hex = "#2563EB"

                elements.append(Paragraph(f"<b>Finding #{idx}: {item['vuln_name']}</b>", ParagraphStyle('FHead', parent=h2_style, fontSize=11)))

                finding_table_data = [
                    [Paragraph("<b>Category:</b>", body_style), Paragraph(item["category"], body_style),
                     Paragraph("<b>Risk Level:</b>", body_style), Paragraph(f"<font color='{color_hex}'><b>{risk_str}</b></font>", body_style)],
                    [Paragraph("<b>Review Status:</b>", body_style), Paragraph(item["review_state"], body_style),
                     Paragraph("<b>Confidence:</b>", body_style), Paragraph(item["confidence_score"], body_style)],
                    [Paragraph("<b>Endpoint:</b>", body_style), Paragraph(f"<code>{item['target_endpoint']}</code>", body_style),
                     Paragraph("<b>Finding ID:</b>", body_style), Paragraph(str(item["id"]), body_style)]
                ]

                t_finding = Table(finding_table_data, colWidths=[90, 180, 90, 180])
                t_finding.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FFFFFF')),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                    ('PADDING', (0,0), (-1,-1), 4),
                ]))
                elements.append(t_finding)
                elements.append(Spacer(1, 4))

                if item["raw_observation"]:
                    elements.append(Paragraph("<b>Collected Evidence:</b>", body_style))
                    elements.append(Paragraph(item["raw_observation"].replace("\n", "<br/>"), code_style))

                if item["remediation_guide"]:
                    elements.append(Paragraph(f"<b>Remediation Guidance:</b> {item['remediation_guide']}", body_style))

                if item["analyst_notes"]:
                    elements.append(Paragraph(f"<b>Analyst Rationale:</b> {item['analyst_notes']}", ParagraphStyle('RNote', parent=body_style, textColor=colors.HexColor('#047857'))))

                elements.append(Spacer(1, 8))
                elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#E2E8F0'), spaceAfter=8))

        doc.build(elements)
        return output_filename