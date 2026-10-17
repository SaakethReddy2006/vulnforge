import httpx
import hashlib
from typing import List, Dict, Any

class SecurityInspector:
    """Performs passive and active HTTP security inspections against authorized target endpoints."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def _build_fingerprint(self, target_id: int, endpoint: str, vuln_name: str, snippet: str) -> str:
        """Generates a unique SHA-256 fingerprint for scan deduplication."""
        raw_seed = f"{target_id}:{endpoint}:{vuln_name}:{snippet}"
        return hashlib.sha256(raw_seed.encode('utf-8')).hexdigest()

    def run_checks(self, target_id: int, target_url: str) -> List[Dict[str, Any]]:
        """Executes custom security inspection checks against the target URL."""
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

            # 3. Permissive CORS Misconfiguration
            cors_origin = headers_lower.get("access-control-allow-origin", "")
            if cors_origin == "*":
                evidence_str = f"Header 'Access-Control-Allow-Origin: *' observed on endpoint {endpoint_str}"
                findings.append({
                    "name": "Permissive Cross-Origin Resource Sharing (CORS) Policy",
                    "category": "Access Control",
                    "risk_level": "Medium",
                    "confidence": "High",
                    "endpoint": endpoint_str,
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted domains instead of wildcards (*).",
                    "evidence": evidence_str,
                    "check_source": "SecurityInspector Engine",
                    "fingerprint": self._build_fingerprint(target_id, endpoint_str, "CORS Wildcard Policy", evidence_str)
                })

            # 4. Server Banner Technology Disclosure
            for banner_header in ["server", "x-powered-by", "x-aspnet-version"]:
                if banner_header in headers_lower:
                    value = headers_lower[banner_header]
                    evidence_str = f"Response header '{banner_header}' disclosed tech stack: '{value}'"
                    findings.append({
                        "name": f"Information Disclosure: {banner_header.title()} Banner",
                        "category": "Information Disclosure",
                        "risk_level": "Info",
                        "confidence": "High",
                        "endpoint": endpoint_str,
                        "remediation": f"Obfuscate or suppress the '{banner_header.title()}' header in web server configuration.",
                        "evidence": evidence_str,
                        "check_source": "SecurityInspector Engine",
                        "fingerprint": self._build_fingerprint(target_id, endpoint_str, f"Info Disclosure ({banner_header})", evidence_str)
                    })

            # 5. Enabled Unsafe HTTP Methods (OPTIONS Check)
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    opt_res = client.options(target_url)
                    allowed_methods = opt_res.headers.get("allow", "").upper()
                    if "TRACE" in allowed_methods or "PUT" in allowed_methods or "DELETE" in allowed_methods:
                        evidence_str = f"Server allowed potentially dangerous HTTP methods: {allowed_methods}"
                        findings.append({
                            "name": "Unsafe HTTP Methods Enabled",
                            "category": "Server Configuration",
                            "risk_level": "Medium",
                            "confidence": "Medium",
                            "endpoint": endpoint_str,
                            "remediation": "Disable unnecessary HTTP verb methods (PUT, DELETE, TRACE) on public application servers.",
                            "evidence": evidence_str,
                            "check_source": "SecurityInspector Engine",
                            "fingerprint": self._build_fingerprint(target_id, endpoint_str, "Unsafe HTTP Methods", evidence_str)
                        })
            except Exception:
                pass

        except httpx.RequestError as exc:
            print(f"[!] Inspection execution warning for {target_url}: {exc}")

        return findings