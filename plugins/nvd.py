"""
NVD (National Vulnerability Database) Plugin for Tyr
Queries the official NVD API for vulnerability information
"""

import time
from typing import Dict, List, Any
import requests
from plugins.base import VulnerabilityPlugin


class NVDPlugin(VulnerabilityPlugin):
    """Plugin for querying National Vulnerability Database"""

    @property
    def name(self) -> str:
        return "nvd"

    @property
    def display_name(self) -> str:
        return "National Vulnerability Database"

    @property
    def description(self) -> str:
        return "Official US government vulnerability database with comprehensive CVE information"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def requires_api_key(self) -> bool:
        return False  # Optional but recommended

    @property
    def api_key_env_var(self) -> str:
        return "NVD_API_KEY"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Reduced delay if API key is provided
        if self.api_key:
            self.delay = kwargs.get("delay", 0.6)
        else:
            self.delay = kwargs.get("delay", 6.0)

    def is_available(self) -> bool:
        """Check if NVD API is available"""
        try:
            response = requests.get(
                self.base_url, params={"resultsPerPage": 1}, timeout=self.timeout
            )
            return response.status_code in [200, 400]  # 400 is OK (missing required params)
        except Exception:
            return False

    def query_vulnerabilities(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """Query NVD database for vulnerabilities"""
        keywords = f"{package_name} {version}"
        params = {"keywordSearch": keywords, "resultsPerPage": 20}

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                self.base_url, params=params, headers=headers, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            # Respect rate limits
            time.sleep(self.delay)

            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve_item = item.get("cve", {})
                if not cve_item:
                    continue

                # Extract CVSS score
                metrics = cve_item.get("metrics", {})
                cvss_score = 0.0

                # Try different CVSS versions
                for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_type in metrics and metrics[metric_type]:
                        cvss_score = (
                            metrics[metric_type][0]
                            .get("cvssData", {})
                            .get("baseScore", 0.0)
                        )
                        break

                # Determine severity
                severity = self._cvss_to_severity(cvss_score)

                # Extract CWE information
                cwes = []
                for weakness in cve_item.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwes.append(desc.get("value"))

                vulnerability = {
                    "id": cve_item.get("id", ""),
                    "source": self.name,
                    "description": cve_item.get("descriptions", [{}])[0].get(
                        "value", "No description available"
                    ),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": [
                        ref.get("url") for ref in cve_item.get("references", [])
                    ],
                    "published": cve_item.get("published", ""),
                    "cwe": cwes,
                }
                vulnerabilities.append(vulnerability)

            return vulnerabilities

        except Exception as e:
            print(f"❌ NVD plugin error for {package_name} {version}: {e}")
            return []

    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        else:
            return "UNKNOWN"
