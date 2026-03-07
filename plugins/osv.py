"""
OSV (Open Source Vulnerabilities) Plugin for Tyr
Queries the OSV.dev database for vulnerability information
"""

import time
from typing import Dict, List, Any
import requests
from plugins.base import VulnerabilityPlugin


class OSVPlugin(VulnerabilityPlugin):
    """Plugin for querying Open Source Vulnerabilities database"""

    @property
    def name(self) -> str:
        return "osv"

    @property
    def display_name(self) -> str:
        return "Open Source Vulnerabilities"

    @property
    def description(self) -> str:
        return "Distributed vulnerability database for open source projects"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def requires_api_key(self) -> bool:
        return False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.base_url = "https://api.osv.dev/v1/query"
        self.delay = kwargs.get("delay", 1.0)

    def is_available(self) -> bool:
        """Check if OSV API is available"""
        try:
            # Try a simple query
            response = requests.post(
                self.base_url,
                json={"package": {"name": "test"}, "version": "1.0.0"},
                timeout=self.timeout,
            )
            return response.status_code in [200, 404]  # 404 is OK (no vulnerabilities found)
        except Exception:
            return False

    def query_vulnerabilities(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """Query OSV database for vulnerabilities"""
        query = {"package": {"name": package_name}, "version": version}

        # Add ecosystem if package type is provided
        if package_type:
            ecosystem_map = {
                "npm": "npm",
                "pypi": "PyPI",
                "gem": "RubyGems",
                "composer": "Packagist",
                "maven": "Maven",
                "cargo": "crates.io",
            }
            ecosystem = ecosystem_map.get(package_type.lower())
            if ecosystem:
                query["package"]["ecosystem"] = ecosystem

        try:
            response = requests.post(
                self.base_url, json=query, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            # Respect rate limits
            time.sleep(self.delay)

            vulnerabilities = []
            for vuln in data.get("vulns", []):
                # Extract CVSS score if available
                cvss_score = 0.0
                if "database_specific" in vuln:
                    if "cvss" in vuln["database_specific"]:
                        cvss_score = vuln["database_specific"]["cvss"]
                    elif "severity" in vuln["database_specific"]:
                        # Some OSV entries use severity ratings
                        severity_str = vuln["database_specific"]["severity"]
                        cvss_score = self._severity_to_cvss(severity_str)

                # Try to extract from severity field
                if cvss_score == 0.0 and "severity" in vuln:
                    for severity_item in vuln.get("severity", []):
                        if severity_item.get("type") == "CVSS_V3":
                            cvss_score = severity_item.get("score", 0.0)
                            break

                severity = self._cvss_to_severity(cvss_score)
                if severity == "UNKNOWN":
                    # Fallback to description analysis
                    severity = self._analyze_severity_from_text(
                        vuln.get("summary", "") + " " + vuln.get("details", "")
                    )

                # Extract references
                references = []
                for ref in vuln.get("references", []):
                    if isinstance(ref, dict):
                        references.append(ref.get("url", ""))
                    else:
                        references.append(str(ref))

                # Extract CWE if available
                cwes = []
                if "database_specific" in vuln and "cwe_ids" in vuln["database_specific"]:
                    cwes = vuln["database_specific"]["cwe_ids"]

                vulnerability = {
                    "id": vuln.get("id", ""),
                    "source": self.name,
                    "description": vuln.get("summary") or vuln.get("details", "No description available"),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": references,
                    "published": vuln.get("published", ""),
                    "cwe": cwes,
                    "affected_versions": self._extract_affected_versions(vuln),
                }
                vulnerabilities.append(vulnerability)

            return vulnerabilities

        except Exception as e:
            print(f"❌ OSV plugin error for {package_name} {version}: {e}")
            return []

    def _extract_affected_versions(self, vuln: Dict) -> str:
        """Extract affected version range from vulnerability data"""
        affected = vuln.get("affected", [])
        if not affected:
            return ""

        ranges = []
        for item in affected:
            for version_range in item.get("ranges", []):
                events = version_range.get("events", [])
                if events:
                    range_str = ", ".join(
                        f"{k}: {v}" for event in events for k, v in event.items()
                    )
                    ranges.append(range_str)

        return "; ".join(ranges) if ranges else ""

    def _severity_to_cvss(self, severity_str: str) -> float:
        """Convert severity string to approximate CVSS score"""
        severity_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MODERATE": 5.5,
            "MEDIUM": 5.5,
            "LOW": 2.5,
        }
        return severity_map.get(severity_str.upper(), 0.0)

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

    def _analyze_severity_from_text(self, text: str) -> str:
        """Analyze text to determine severity when CVSS is not available"""
        text_lower = text.lower()

        critical_keywords = [
            "critical",
            "remote code execution",
            "rce",
            "arbitrary code execution",
        ]
        if any(kw in text_lower for kw in critical_keywords):
            return "CRITICAL"

        high_keywords = ["high", "sql injection", "xss", "csrf"]
        if any(kw in text_lower for kw in high_keywords):
            return "HIGH"

        medium_keywords = ["medium", "moderate", "denial of service", "dos"]
        if any(kw in text_lower for kw in medium_keywords):
            return "MEDIUM"

        return "LOW"
