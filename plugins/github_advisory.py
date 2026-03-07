"""
GitHub Advisory Database Plugin for Tyr
Queries GitHub's security advisory database
"""

import time
from typing import Dict, List, Any
import requests
from plugins.base import VulnerabilityPlugin


class GitHubAdvisoryPlugin(VulnerabilityPlugin):
    """Plugin for querying GitHub Security Advisory Database"""

    @property
    def name(self) -> str:
        return "github-advisory"

    @property
    def display_name(self) -> str:
        return "GitHub Security Advisory"

    @property
    def description(self) -> str:
        return "GitHub's curated database of security vulnerabilities"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def requires_api_key(self) -> bool:
        return False  # Optional - higher rate limits with token

    @property
    def api_key_env_var(self) -> str:
        return "GITHUB_TOKEN"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.base_url = "https://api.github.com/graphql"
        self.delay = kwargs.get("delay", 1.0)

    def is_available(self) -> bool:
        """Check if GitHub API is available"""
        try:
            headers = {"User-Agent": "Tyr-Scanner"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            # Simple query to check availability
            response = requests.get(
                "https://api.github.com", headers=headers, timeout=self.timeout
            )
            return response.status_code in [200, 304]
        except Exception:
            return False

    def query_vulnerabilities(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """Query GitHub Advisory database for vulnerabilities"""
        
        # Map package types to GitHub ecosystems
        ecosystem_map = {
            "npm": "NPM",
            "pypi": "PIP",
            "gem": "RUBYGEMS",
            "composer": "COMPOSER",
            "maven": "MAVEN",
            "cargo": "RUST",
            "nuget": "NUGET",
        }

        ecosystem = ecosystem_map.get(package_type.lower() if package_type else "")
        if not ecosystem:
            # Can't query without ecosystem information
            return []

        # GraphQL query to search for vulnerabilities
        query = """
        query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
          securityVulnerabilities(first: 20, package: $package, ecosystem: $ecosystem) {
            nodes {
              advisory {
                ghsaId
                summary
                description
                severity
                publishedAt
                references {
                  url
                }
                cvss {
                  score
                }
                cwes(first: 5) {
                  nodes {
                    cweId
                    name
                  }
                }
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """

        variables = {"package": package_name, "ecosystem": ecosystem}

        headers = {
            "User-Agent": "Tyr-Scanner",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.post(
                self.base_url,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            # Respect rate limits
            time.sleep(self.delay)

            vulnerabilities = []
            
            if "errors" in data:
                print(f"⚠️  GitHub API error: {data['errors']}")
                return []

            nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])

            for node in nodes:
                advisory = node.get("advisory", {})
                if not advisory:
                    continue

                # Check if this version is affected
                version_range = node.get("vulnerableVersionRange", "")
                if not self._version_affected(version, version_range):
                    continue

                # Extract CVSS score
                cvss_score = 0.0
                cvss_data = advisory.get("cvss", {})
                if cvss_data:
                    cvss_score = cvss_data.get("score", 0.0)

                # Get severity
                severity = advisory.get("severity", "UNKNOWN").upper()
                if severity == "MODERATE":
                    severity = "MEDIUM"

                # Extract CWEs
                cwes = []
                cwe_nodes = advisory.get("cwes", {}).get("nodes", [])
                for cwe in cwe_nodes:
                    cwes.append(cwe.get("cweId", ""))

                # Extract references
                references = [
                    ref.get("url", "")
                    for ref in advisory.get("references", [])
                ]

                # Get patched version
                patched_version = node.get("firstPatchedVersion", {})
                remediation = "Update to a patched version"
                if patched_version:
                    remediation = f"Update to version {patched_version.get('identifier', 'latest')}"

                vulnerability = {
                    "id": advisory.get("ghsaId", ""),
                    "source": self.name,
                    "description": advisory.get("description") or advisory.get("summary", "No description available"),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": references,
                    "published": advisory.get("publishedAt", ""),
                    "cwe": cwes,
                    "affected_versions": version_range,
                    "remediation": remediation,
                }
                vulnerabilities.append(vulnerability)

            return vulnerabilities

        except Exception as e:
            print(f"❌ GitHub Advisory plugin error for {package_name} {version}: {e}")
            return []

    def _version_affected(self, version: str, version_range: str) -> bool:
        """
        Simple version range check.
        This is a basic implementation - a full implementation would use
        semantic versioning libraries.
        """
        # For now, return True to include all vulnerabilities
        # A proper implementation would parse version ranges like "< 2.0.0"
        # and compare against the actual version
        return True
