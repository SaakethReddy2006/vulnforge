import httpx
import hashlib
from typing import List, Dict, Any

class SecurityInspector:
    """Automates HTTP response security inspection and fingerprint deduplication."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def _build_fingerprint(self, target_id: int, endpoint: str, vuln_name: str, snippet: str) -> str:
        """Generates a SHA-256 fingerprint hash to prevent duplicate findings."""
        raw_seed = f"{target_id}:{endpoint}:{vuln_name}:{snippet}"
        return hashlib.sha256(raw_seed.encode('utf-8')).hexdigest()

    def run_checks(self, target_id: int, target_url: str) -> List[Dict[str, Any]]:
        """Executes custom inspection logic against an authorized target URL."""
        findings = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(target_url)

            endpoint_str = str(response.url)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            # 1. Missing HTTP Security Headers
            header_rules = {
                "Content-Security-Policy": ("Medium", "High", "Configure a strict Content-Security-Policy (CSP) header to mitigate XSS attacks."),
                "Strict-Transport-Security": ("Low", "High", "Set HSTS header with max-age to enforce HTTPS communication."),
                "X-Frame-Options": ("Low", "High", "Configure X-Frame-Options to DENY or SAMEORIGIN to prevent Clickjacking."),
                "X-Content-Type-Options": ("Low", "High", "Set X-Content-Type-Options: nosniff to stop MIME-type sniffing.")
            }

            for header_name, (risk, conf, remediation) in header_rules.items():
                if header_name.lower() not in headers_lower:
                    evidence_str = f"Header '{header_name}' was missing in HTTP response from {endpoint_str}"
                    findings.append({
                        "name": f"Missing Security Header: {header_name}",
                        "category": "HTTP Security Headers",
                        "risk_level": risk,
                        "confidence": conf,
                        "endpoint": endpoint_str,
                        "remediation": remediation,
                        "evidence": evidence_str,
                        "check_source": "SecurityInspector Engine",
                        "fingerprint": self._build_fingerprint(target_id, endpoint_str, f"Missing Header: {header_name}", evidence_str)
                    })

            # 2. Insecure Cookie Attributes
            for cookie in response.cookies.jar:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' flag")
                if not getattr(cookie, "rest", {}).get("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
                    issues.append("Missing 'HttpOnly' flag")

                if issues:
                    evidence_str = f"Cookie '{cookie.name}' has security flaws: {', '.join(issues)}"
                    findings.append({
                        "name": f"Insecure Cookie Flag ({cookie.name})",
                        "category": "Session Management",
                        "risk_level": "Low",
                        "confidence": "High",
                        "endpoint": endpoint_str,
                        "remediation": f"Ensure Secure and HttpOnly flags are set on sensitive cookie '{cookie.name}'.",
                        "evidence": evidence_str,
                        "check_source": "SecurityInspector Engine",
                        "fingerprint": self._build_fingerprint(target_id, endpoint_str, f"Insecure Cookie ({cookie.name})", evidence_str)
                    })

            # 3. Server Version Disclosure
            for banner_header in ["server", "x-powered-by"]:
                if banner_header in headers_lower:
                    value = headers_lower[banner_header]
                    evidence_str = f"Response header '{banner_header}' disclosed tech stack: '{value}'"
                    findings.append({
                        "name": f"Information Disclosure: {banner_header.title()} Banner",
                        "category": "Information Disclosure",
                        "risk_level": "Info",
                        "confidence": "High",
                        "endpoint": endpoint_str,
                        "remediation": f"Obfuscate or suppress the '{banner_header.title()}' header in server configuration.",
                        "evidence": evidence_str,
                        "check_source": "SecurityInspector Engine",
                        "fingerprint": self._build_fingerprint(target_id, endpoint_str, f"Info Disclosure ({banner_header})", evidence_str)
                    })

        except httpx.RequestError as exc:
            print(f"[!] Inspection execution warning for {target_url}: {exc}")

        return findings