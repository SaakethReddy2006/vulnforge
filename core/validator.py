from urllib.parse import urlparse
from typing import Optional, List

class ScopeValidator:
    """Enforces target URL structure and authorized testing scope boundaries."""

    def __init__(self, allowed_domains: Optional[List[str]] = None):
        # Default restricted lab allowlist
        self.allowed_domains = allowed_domains or [
            "localhost", "127.0.0.1", "juiceshop.local", "dvwa.local", "crapi.local"
        ]

    def validate_target(self, url: str) -> tuple[bool, str]:
        """Verifies if a target URL is properly formatted and within authorized scope."""
        if not url or not url.strip():
            return False, "Target URL cannot be empty."

        try:
            parsed = urlparse(url.strip())
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL structure. Scheme required (e.g., http:// or https://)."

            if parsed.scheme not in ["http", "https"]:
                return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP/HTTPS protocols allowed."

            # Extract host without port number
            host = parsed.netloc.split(":")[0].lower()

            if host in [d.lower() for d in self.allowed_domains]:
                return True, f"Target host '{host}' is explicitly authorized."
            else:
                return False, f"Scope Violation: Host '{host}' is outside authorized testing bounds."

        except Exception as e:
            return False, f"URL Parsing Error: {str(e)}"