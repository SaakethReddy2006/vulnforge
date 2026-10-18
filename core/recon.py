import asyncio
import socket
import urllib.parse
import urllib.request
import json
import re
from typing import List, Dict, Any, Set
from core.validator import ScopeValidator

class ReconEngine:
    """Automated passive subdomain discovery, async port scanning, and framework fingerprinting."""

    COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]

    def __init__(self, validator: ScopeValidator = None):
        self.validator = validator or ScopeValidator()

    def discover_subdomains(self, domain: str) -> List[str]:
        """Passively queries crt.sh Certificate Transparency logs for subdomains."""
        # Clean domain string
        clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        
        url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
        subdomains: Set[str] = set()

        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "VulnForge-ReconEngine/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            # Strip wildcard prefixes
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and not sub.startswith("*"):
                                subdomains.add(sub)
        except Exception:
            # Fallback to local target domain if external crt.sh is unreachable/rate-limited
            subdomains.add(clean_domain)

        # Filter discovered assets through ScopeValidator to ensure no scope leakage
        valid_assets = []
        for sub in subdomains:
            test_url = f"http://{sub}"
            is_valid, _ = self.validator.validate_target(test_url)
            if is_valid:
                valid_assets.append(sub)

        return sorted(valid_assets)

    async def _check_port(self, host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
        """Asynchronously checks if a specific TCP port is open."""
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return {"port": port, "state": "open"}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed"}

    async def scan_ports_async(self, host: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Scans a list of TCP ports concurrently using asyncio."""
        target_ports = ports or self.COMMON_PORTS
        clean_host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        tasks = [self._check_port(clean_host, port) for port in target_ports]
        results = await asyncio.gather(*tasks)
        
        return [res for res in results if res["state"] == "open"]

    def run_port_scan(self, host: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Synchronous wrapper for async port scanning."""
        return asyncio.run(self.scan_ports_async(host, ports))

    def fingerprint_tech_stack(self, url: str) -> Dict[str, Any]:
        """Parses HTTP response headers and meta tags to identify frameworks and web servers."""
        is_valid, msg = self.validator.validate_target(url)
        if not is_valid:
            return {"error": f"Scope Violation: {msg}"}

        fingerprints = {
            "web_server": "Unknown",
            "frameworks": [],
            "headers": {}
        }

        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "VulnForge-ReconEngine/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = dict(resp.headers)
                fingerprints["headers"] = headers

                # Server Banner
                if "Server" in headers:
                    fingerprints["web_server"] = headers["Server"]

                # X-Powered-By
                if "X-Powered-By" in headers:
                    fingerprints["frameworks"].append(headers["X-Powered-By"])

                # Basic HTML Banner inspection
                body = resp.read(4096).decode("utf-8", errors="ignore")
                if "wp-content" in body:
                    fingerprints["frameworks"].append("WordPress")
                if "React" in body or "react-root" in body:
                    fingerprints["frameworks"].append("React")
                if "ng-app" in body or "angular" in body:
                    fingerprints["frameworks"].append("Angular")

        except Exception as e:
            fingerprints["error"] = str(e)

        return fingerprints