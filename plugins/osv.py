"""
OSV (Open Source Vulnerabilities) Plugin for Tyr
Queries the OSV.dev database for vulnerability information
"""

import math
import time
from typing import Any, Dict, List, Optional
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
                "go": "Go",
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
                cvss_score = self._extract_cvss_score(vuln)
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

    def _extract_cvss_score(self, vuln: Dict) -> float:
        """
        A numeric CVSS score for an OSV entry, or 0.0 when it has none we can read.

        OSV gives `severity[].score` as a CVSS vector string ("CVSS:3.1/AV:N/..."),
        not a number. Comparing that string with a number raised TypeError, and the
        caller's broad except then dropped every advisory of the package. Anything
        unreadable here falls back to 0.0, so the advisory is still reported and its
        severity comes from the text instead.
        """
        specific = vuln.get("database_specific") or {}
        if isinstance(specific, dict):
            score = _as_score(specific.get("cvss"))
            if score is not None:
                return score
            if isinstance(specific.get("severity"), str):
                score = self._severity_to_cvss(specific["severity"])
                if score:
                    return score

        for item in vuln.get("severity") or []:
            if isinstance(item, dict) and item.get("type") == "CVSS_V3":
                score = _as_score(item.get("score"))
                if score is not None:
                    return score
        return 0.0

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


def _as_score(value) -> Optional[float]:
    """A CVSS score from a number, a numeric string, a CVSS 3.x vector or {"score": ...}."""
    if isinstance(value, dict):
        value = value.get("score")
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if 0.0 <= value <= 10.0 else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return cvss3_base_score(value)
        return number if 0.0 <= number <= 10.0 else None
    return None


# CVSS v3.x base metric weights (FIRST, CVSS v3.1 specification, section 7.4).
_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs more when the scope changes.
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= value, float-safe."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector) -> Optional[float]:
    """
    The base score of a CVSS v3.0/v3.1 vector string, or None if it is not one.

    Only the eight base metrics are used; temporal and environmental metrics after
    them are ignored, as they are for a base score.
    """
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, sep, val = part.partition(":")
        if not sep:
            return None
        metrics[key] = val
    try:
        scope = metrics["S"]
        av, ac, ui = (_CVSS3_WEIGHTS[m][metrics[m]] for m in ("AV", "AC", "UI"))
        pr = _CVSS3_PR[scope][metrics["PR"]]
        c, i, a = (_CVSS3_WEIGHTS[m][metrics[m]] for m in ("C", "I", "A"))
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))
