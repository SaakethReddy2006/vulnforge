import urllib.request
import urllib.parse
import json
from typing import Dict, Any, List

class VulnerabilityIntelligence:
    """Enriches detected technology banners with live CVE data from NVD and exploit probabilities from EPSS."""

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_epss_score(self, cve_id: str) -> Dict[str, Any]:
        """Fetches EPSS probability score and percentile for a specific CVE ID."""
        cve_id = cve_id.strip().upper()
        url = f"{self.EPSS_API_URL}?cve={cve_id}"

        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "VulnForge-SecOps/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("data"):
                        epss_data = data["data"][0]
                        return {
                            "cve": cve_id,
                            "epss_score": float(epss_data.get("epss", 0.0)),
                            "percentile": float(epss_data.get("percentile", 0.0))
                        }
        except Exception:
            pass

        return {"cve": cve_id, "epss_score": 0.0, "percentile": 0.0}

    def search_cves_by_keyword(self, keyword: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Queries NVD API for recent CVEs matching a technology keyword or server banner."""
        encoded_keyword = urllib.parse.quote(keyword)
        url = f"{self.NVD_API_URL}?keywordSearch={encoded_keyword}&resultsPerPage={limit}"

        cve_results = []

        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "VulnForge-SecOps/1.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode('utf-8'))
                    vulnerabilities = payload.get("vulnerabilities", [])

                    for item in vulnerabilities:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id")
                        
                        descriptions = cve.get("descriptions", [])
                        summary = descriptions[0].get("value") if descriptions else "No description available."

                        # Extract CVSS v3 metrics if available
                        metrics = cve.get("metrics", {})
                        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                        
                        severity = "UNKNOWN"
                        score = 0.0
                        if cvss_v3:
                            cvss_data = cvss_v3[0].get("cvssData", {})
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            score = cvss_data.get("baseScore", 0.0)

                        # Enrich with EPSS score
                        epss_info = self.fetch_epss_score(cve_id)

                        cve_results.append({
                            "cve_id": cve_id,
                            "summary": summary[:200] + "..." if len(summary) > 200 else summary,
                            "cvss_score": score,
                            "severity": severity,
                            "epss_probability": f"{epss_info['epss_score'] * 100:.2f}%",
                            "epss_percentile": f"{epss_info['percentile'] * 100:.2f}%"
                        })
        except Exception as e:
            cve_results.append({
                "error": f"NVD Intelligence lookup unavailable: {str(e)}"
            })

        return cve_results