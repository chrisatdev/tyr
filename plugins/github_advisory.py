"""
GitHub Advisory Database Plugin for Tyr
Queries GitHub's security advisory database
"""

import re
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
                if not self._version_affected(version, version_range, ecosystem=ecosystem):
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

    @property
    def accepts_raw_version(self) -> bool:
        # Filters by range, so it needs to tell an exact version from a range.
        return True

    def _version_affected(
        self, version: str, version_range: str, exact: bool = False, ecosystem: str = None
    ) -> bool:
        """
        Whether `version` falls inside a GitHub `vulnerableVersionRange`.

        GitHub writes a range as comma-separated clauses that must all hold,
        e.g. ">= 7.0.0, <= 7.3.6", "< 1.55.1" or "= 6.4.4". When the version
        or the range cannot be understood, the advisory is kept: a false
        positive is better than a hidden vulnerability. That includes a range
        specifier such as "^1.2.0", which may resolve to an affected version:
        only an exact version is ever filtered.

        A spec with fewer than three numeric parts ("4.17", "18") is a range in
        npm (4.17.x), so it is only compared as a version when the caller says it
        is `exact`, as a lockfile entry is.

        A "-suffix" is only ordered as a semver prerelease in ecosystems that use
        semver (npm, crates.io, Go, NuGet). Elsewhere it means something else
        (PyPI "2.0.0-1" is a post-release, after 2.0.0), so it keeps the advisory.
        """
        semver = (ecosystem or "").upper() in _SEMVER_ECOSYSTEMS
        current = _parse_version(version, semver)
        if current is None or not version_range or not version_range.strip():
            return True
        if not exact and len(current[0]) < 3:
            return True

        for clause in version_range.split(","):
            match = _CLAUSE.match(clause.strip())
            if not match:
                return True
            bound = _parse_version(match.group(2), semver)
            if bound is None:
                return True
            if not _OPERATORS[match.group(1) or "="](_compare(current, bound)):
                return False
        return True


_CLAUSE = re.compile(r"^(>=|<=|>|<|=)?\s*(\S+)$")
_OPERATORS = {
    ">=": lambda c: c >= 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    "<": lambda c: c < 0,
    "=": lambda c: c == 0,
}
# Only semver-style prerelease tags sort below their release. Maven "-RELEASE" or
# "-SP1" and PyPI "-1" post-releases do not, so those do not parse as versions.
_PRERELEASE_ID = r"(?:\d+|(?:alpha|beta|rc|pre|dev)\d*)"
_VERSION = re.compile(
    rf"^v?(\d+(?:\.\d+)*)(?:-({_PRERELEASE_ID}(?:\.{_PRERELEASE_ID})*))?(?:\+[0-9A-Za-z.-]+)?$",
    re.IGNORECASE,
)


_SEMVER_ECOSYSTEMS = {"NPM", "RUST", "GO", "NUGET"}


def _parse_version(text, semver=False):
    """(release numbers, prerelease identifiers) or None when not a version.

    Outside semver ecosystems any prerelease-looking suffix is not a version we
    can order, so it returns None and the caller keeps the advisory.
    """
    match = _VERSION.match((text or "").strip())
    if not match or (match.group(2) and not semver):
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    prerelease = tuple(match.group(2).lower().split(".")) if match.group(2) else ()
    return release, prerelease


def _compare(a, b) -> int:
    """Semver-style ordering: -1, 0 or 1. Missing parts count as zero."""
    (release_a, pre_a), (release_b, pre_b) = a, b
    width = max(len(release_a), len(release_b))
    padded_a = release_a + (0,) * (width - len(release_a))
    padded_b = release_b + (0,) * (width - len(release_b))
    if padded_a != padded_b:
        return -1 if padded_a < padded_b else 1
    # A prerelease sorts before its release: 5.0.0-rc.1 < 5.0.0.
    if pre_a == pre_b:
        return 0
    if not pre_a or not pre_b:
        return 1 if not pre_a else -1
    for x, y in zip(pre_a, pre_b):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1  # numeric identifiers sort first
        return -1 if x < y else 1
    return -1 if len(pre_a) < len(pre_b) else 1
