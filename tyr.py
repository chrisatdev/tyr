#!/usr/bin/env python3
"""
Tyr - Vulnerability Scanner
Security scanner that analyzes projects for vulnerable dependencies and suspicious code patterns.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List

import requests

__version__ = "1.1.0"


class Colors:
    """Terminal color codes"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def smart_truncate(text, max_length=100):
    """Intelligent truncation that cleans problematic characters and maintains complete words"""
    if not text:
        return ""

    # Clean problematic characters: quotes, colons, line breaks, etc.
    clean_text = re.sub(r'[\n\r\t:"\']+', " ", str(text))
    # Collapse multiple spaces into one
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    if len(clean_text) <= max_length:
        return clean_text

    # Truncate and find the last space before the limit
    truncated = clean_text[:max_length]
    last_space = truncated.rfind(" ")

    if last_space > max_length * 0.7:  # If we find a space at a reasonable position
        return truncated[:last_space] + "..."
    else:
        return truncated + "..."


class NVDClient:
    """Client for National Vulnerability Database"""

    def __init__(self, api_key: str = None, delay: float = 6.0):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        # Reduced delay if API key is provided
        self.delay = 0.6 if api_key else delay

    def query_vulnerabilities(self, package_name: str, version: str) -> List[Dict]:
        """
        Query NVD database for vulnerabilities in a specific package version
        """
        # NVD search by keyword (package name and version)
        keywords = f"{package_name} {version}"
        params = {"keywordSearch": keywords, "resultsPerPage": 20}

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(self.base_url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            # Add delay to respect rate limits
            time.sleep(self.delay)

            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve_item = item.get("cve", {})
                if cve_item:
                    # Get CVSS score if available
                    metrics = cve_item.get("metrics", {})
                    cvss_score = 0.0

                    # Try different metric versions
                    for metric_type in [
                        "cvssMetricV31",
                        "cvssMetricV30",
                        "cvssMetricV2",
                    ]:
                        if metric_type in metrics and metrics[metric_type]:
                            cvss_score = (
                                metrics[metric_type][0]
                                .get("cvssData", {})
                                .get("baseScore", 0.0)
                            )
                            break

                    vulnerability = {
                        "id": cve_item.get("id", ""),
                        "source": "NVD",
                        "description": cve_item.get("descriptions", [{}])[0].get(
                            "value", ""
                        ),
                        "cvss_score": cvss_score,
                        "references": [
                            ref.get("url") for ref in cve_item.get("references", [])
                        ],
                        "published": cve_item.get("published", ""),
                    }
                    vulnerabilities.append(vulnerability)

            return vulnerabilities
        except Exception as e:
            print(
                f"{Colors.RED}Error querying NVD for {package_name} {version}: {e}"
                f"{Colors.END}"
            )
            return []


class OSVClient:
    """Client for Open Source Vulnerabilities database"""

    def __init__(self, delay: float = 1.0):
        self.base_url = "https://api.osv.dev/v1/query"
        self.delay = delay

    def query_vulnerabilities(self, package_name: str, version: str) -> List[Dict]:
        """
        Query OSV database for vulnerabilities in a specific package version
        """
        query = {"package": {"name": package_name}, "version": version}

        try:
            response = requests.post(self.base_url, json=query)
            response.raise_for_status()
            data = response.json()

            # Add delay to be respectful to the API
            time.sleep(self.delay)

            vulnerabilities = []
            for vuln in data.get("vulns", []):
                vulnerability = {
                    "id": vuln.get("id", ""),
                    "source": "OSV",
                    "summary": vuln.get("summary", ""),
                    "details": vuln.get("details", ""),
                    "references": vuln.get("references", []),
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                }

                # Try to extract CVSS score if available
                if "database_specific" in vuln and "cvss" in vuln["database_specific"]:
                    vulnerability["cvss_score"] = vuln["database_specific"]["cvss"]
                else:
                    vulnerability["cvss_score"] = 0.0

                vulnerabilities.append(vulnerability)

            return vulnerabilities
        except Exception as e:
            print(
                f"{Colors.RED}Error querying OSV for {package_name} {version}: {e}{
                    Colors.END
                }"
            )
            return []


class CodeScanner:
    """Scanner for suspicious code patterns"""

    def __init__(self):
        self.patterns = [
            {
                "name": "Hardcoded Credential in XML",
                "pattern": r"<Value>([A-Z0-9]{20,}|[a-zA-Z0-9\-_]{20,})</Value>",
                "risk": "CRITICAL",
                "description": "Hardcoded credential found in XML element",
                "recommendation": "Remove hardcoded credentials and use secure secret management",
            },
            {
                "name": "Hardcoded Password",
                "pattern": r'(password|pwd|pass)\s*=\s*["\'][^"\']+["\']',
                "risk": "CRITICAL",
                "description": "Hardcoded credentials found",
                "recommendation": "Use environment variables or secure secret management",
            },
            {
                "name": "Potential SQL Injection",
                "pattern": r"(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b).*(\+|\%s|\{}).*",
                "risk": "HIGH",
                "description": "String concatenation in SQL query detected",
                "recommendation": "Use parameterized queries or ORM",
            },
            {
                "name": "Debug Mode Enabled",
                "pattern": r"(debug\s*=\s*True|DEBUG\s*=\s*True)",
                "risk": "LOW",
                "description": "Debug mode enabled in code",
                "recommendation": "Disable debug mode in production",
            },
            {
                "name": "Hardcoded API Key",
                "pattern": r'(api[_-]?key|apikey|secret[_-]?key)\s*=\s*["\'][^"\']+["\']',
                "risk": "HIGH",
                "description": "Hardcoded API key found",
                "recommendation": "Use environment variables for API keys",
            },
            {
                "name": "Insecure Random",
                "pattern": r"random\.\w+\(\)|Math\.random\(\)",
                "risk": "MEDIUM",
                "description": "Using insecure random number generation",
                "recommendation": "Use cryptographically secure random functions",
            },
            {
                "name": "HTTP Without TLS",
                "pattern": r'http://[^\s"\']+',
                "risk": "MEDIUM",
                "description": "HTTP URL without TLS encryption",
                "recommendation": "Use HTTPS for all external requests",
            },
        ]

    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single file for suspicious patterns
        """
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    for pattern_info in self.patterns:
                        if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                            findings.append(
                                {
                                    "file": str(file_path),
                                    "line": i,
                                    "code": line.strip(),
                                    "pattern": pattern_info["name"],
                                    "risk": pattern_info["risk"],
                                    "description": pattern_info["description"],
                                    "recommendation": pattern_info["recommendation"],
                                }
                            )
        except Exception as e:
            print(
                f"{Colors.YELLOW}Warning: Could not scan {file_path}: {e}{Colors.END}"
            )

        return findings

    def scan_directory(self, directory: Path) -> List[Dict]:
        """
        Scan all code files in directory for suspicious patterns
        """
        findings = []
        code_extensions = {
            ".py",
            ".js",
            ".java",
            ".php",
            ".rb",
            ".go",
            ".c",
            ".cpp",
            ".h",
            ".sh",
            ".cs",
            ".ts",
            ".jsx",
            ".tsx",
            ".xml",
        }

        for ext in code_extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if file_path.is_file():
                    file_findings = self.scan_file(file_path)
                    findings.extend(file_findings)

        return findings


class TyrScanner:
    """Main vulnerability scanner class"""

    def __init__(
        self,
        nvd_api_key: str = None,
        delay: float = 1.0,
        enable_code_scan: bool = False,
    ):
        self.nvd_client = NVDClient(nvd_api_key, delay)
        self.osv_client = OSVClient(delay)
        self.code_scanner = CodeScanner() if enable_code_scan else None
        self.colors = Colors()

    def print_banner(self):
        """Print the application banner"""
        banner = f"""
{self.colors.CYAN}{self.colors.BOLD}
╔══════════════════════════════════════════╗
║                                          ║
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v{__version__}          ║
║          by Christian Benitez            ║
║         cbenitezdiaz@gmail.com           ║
║                                          ║
╚══════════════════════════════════════════╝
{self.colors.END}

Tyr - Vulnerability Scanner v{__version__}
==================================================
"""
        print(banner)

    def find_dependency_files(self, project_path: Path) -> List[Path]:
        """Find dependency files in the project"""
        dependency_files = []
        patterns = [
            "package.json",  # Node.js
            "composer.json",  # PHP
            "requirements.txt",  # Python
            "Gemfile",  # Ruby
            "pom.xml",  # Java Maven
            "build.gradle",  # Java Gradle
            "Cargo.toml",  # Rust
            "Dockerfile",  # Docker
        ]

        for pattern in patterns:
            for file_path in project_path.rglob(pattern):
                if file_path.is_file():
                    dependency_files.append(file_path)

        return dependency_files

    def parse_dependencies(self, file_path: Path) -> List[Dict]:
        """Parse dependencies from various file types"""
        dependencies = []

        try:
            if file_path.name == "package.json":
                with open(file_path) as f:
                    data = json.load(f)
                    # Main dependencies
                    for name, version in data.get("dependencies", {}).items():
                        dependencies.append(
                            {"name": name, "version": version, "type": "npm"}
                        )
                    # Dev dependencies
                    for name, version in data.get("devDependencies", {}).items():
                        dependencies.append(
                            {"name": name, "version": version, "type": "npm"}
                        )

            elif file_path.name == "requirements.txt":
                with open(file_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Basic parsing - handle cases like "package==1.0.0"
                            if "==" in line:
                                name, version = line.split("==", 1)
                                dependencies.append(
                                    {
                                        "name": name.strip(),
                                        "version": version.strip(),
                                        "type": "pypi",
                                    }
                                )
                            elif ">=" in line or "<=" in line:
                                # Skip complex version specifications for now
                                continue
                            else:
                                # Just the package name
                                dependencies.append(
                                    {"name": line, "version": "unknown", "type": "pypi"}
                                )

            elif file_path.name == "composer.json":
                with open(file_path) as f:
                    data = json.load(f)
                    for name, version in data.get("require", {}).items():
                        dependencies.append(
                            {"name": name, "version": version, "type": "composer"}
                        )

            elif file_path.name == "Gemfile":
                with open(file_path) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("gem "):
                            # Extract gem name and version
                            parts = line.split("'") if "'" in line else line.split('"')
                            if len(parts) >= 2:
                                name = parts[1]
                                version = "unknown"
                                if len(parts) >= 4 and "," in parts[2]:
                                    version = parts[3] if len(parts) > 3 else "unknown"
                                dependencies.append(
                                    {"name": name, "version": version, "type": "gem"}
                                )

            # Add more parsers for other file types as needed...

        except Exception as e:
            print(
                f"{self.colors.YELLOW}Warning: Could not parse {file_path}: {e}{
                    self.colors.END
                }"
            )

        return dependencies

    def clean_version(self, version: str) -> str:
        """Clean version string from package managers"""
        # Remove version prefixes and clean up
        version = (
            version.replace("^", "")
            .replace("~", "")
            .replace(">", "")
            .replace("<", "")
            .replace("=", "")
        )
        version = version.split("-")[0]  # Remove pre-release tags
        return version.strip()

    def scan_vulnerabilities(self, dependencies: List[Dict]) -> List[Dict]:
        """Scan dependencies for vulnerabilities using multiple sources"""
        vulnerabilities = []

        for dep in dependencies:
            clean_ver = self.clean_version(dep["version"])
            if clean_ver == "unknown":
                continue

            print(f"🔍 Checking {dep['name']} {clean_ver}...")

            # Query both NVD and OSV
            nvd_vulns = self.nvd_client.query_vulnerabilities(dep["name"], clean_ver)
            osv_vulns = self.osv_client.query_vulnerabilities(dep["name"], clean_ver)

            # Combine and deduplicate vulnerabilities
            all_vulns = nvd_vulns + osv_vulns
            seen_ids = set()

            for vuln in all_vulns:
                vuln_id = vuln.get("id")
                if vuln_id and vuln_id not in seen_ids:
                    seen_ids.add(vuln_id)

                    # Determine vulnerability type based on description
                    vuln_type = self.determine_vulnerability_type(
                        vuln.get("description") or vuln.get("summary", "")
                    )

                    vulnerability = {
                        "package": dep["name"],
                        "version": clean_ver,
                        "cve": vuln_id,
                        "source": vuln.get("source", "Unknown"),
                        "type": vuln_type,
                        "description": vuln.get("description")
                        or vuln.get("summary", "No description available"),
                        "cvss_score": vuln.get("cvss_score", 0.0),
                        "severity": self.assess_severity(vuln),
                        "references": vuln.get("references", []),
                        "remediation": "Update to a patched version",
                    }
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def determine_vulnerability_type(self, description: str) -> str:
        """Determine vulnerability type based on description content"""
        desc_lower = description.lower()

        if any(
            word in desc_lower
            for word in ["code injection", "remote code execution", "rce"]
        ):
            return "Code Injection"
        elif any(word in desc_lower for word in ["sql injection", "sqli"]):
            return "SQL Injection"
        elif any(word in desc_lower for word in ["xss", "cross-site scripting"]):
            return "XSS"
        elif any(word in desc_lower for word in ["csrf", "cross-site request forgery"]):
            return "CSRF"
        elif any(word in desc_lower for word in ["buffer overflow", "stack overflow"]):
            return "Buffer Overflow"
        elif any(word in desc_lower for word in ["privilege escalation"]):
            return "Privilege Escalation"
        elif any(
            word in desc_lower for word in ["information disclosure", "info disclosure"]
        ):
            return "Information Disclosure"
        elif any(word in desc_lower for word in ["denial of service", "dos", "ddos"]):
            return "Denial of Service"
        else:
            return "Security Issue"

    def assess_severity(self, vulnerability: Dict) -> str:
        """Assess vulnerability severity based on CVSS score"""
        cvss_score = vulnerability.get("cvss_score", 0.0)

        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_report(
        self,
        vulnerabilities: List[Dict],
        code_findings: List[Dict],
        project_name: str,
        output_file: str,
        project_path: str,
    ):
        """Generate Markdown report"""
        with open(output_file, "w") as f:
            f.write(f"# Tyr Security Report - {project_name}\n\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Project Path:** {project_path}\n\n")

            # Vulnerability Summary
            vuln_count = len(vulnerabilities)
            critical_count = sum(
                1 for v in vulnerabilities if v["severity"] == "CRITICAL"
            )
            high_count = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
            medium_count = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
            low_count = sum(1 for v in vulnerabilities if v["severity"] == "LOW")

            f.write("## 📊 Executive Summary\n\n")
            f.write(f"- **Total Vulnerabilities:** {vuln_count}\n")
            f.write(f"- **Critical:** {critical_count}\n")
            f.write(f"- **High:** {high_count}\n")
            f.write(f"- **Medium:** {medium_count}\n")
            f.write(f"- **Low:** {low_count}\n")

            if code_findings:
                finding_count = len(code_findings)
                critical_findings = sum(
                    1 for cf in code_findings if cf["risk"] == "CRITICAL"
                )
                high_findings = sum(1 for cf in code_findings if cf["risk"] == "HIGH")
                medium_findings = sum(
                    1 for cf in code_findings if cf["risk"] == "MEDIUM"
                )
                low_findings = sum(1 for cf in code_findings if cf["risk"] == "LOW")

                f.write(f"- **Suspicious Code Patterns:** {finding_count}\n")
                f.write(f"- **Critical Risk Patterns:** {critical_findings}\n")
                f.write(f"- **High Risk Patterns:** {high_findings}\n")
                f.write(f"- **Medium Risk Patterns:** {medium_findings}\n")
                f.write(f"- **Low Risk Patterns:** {low_findings}\n")

            f.write("\n## 🚨 Vulnerabilities\n\n")

            if vulnerabilities:
                # Colors for each severity level
                severity_colors = {
                    "CRITICAL": "#FF4444",  # Intense red
                    "HIGH": "#FF6B35",  # Reddish orange
                    "MEDIUM": "#FFA500",  # Orange
                    "LOW": "#4CAF50",  # Green
                    "UNKNOWN": "#757575",  # Gray
                }

                f.write(
                    "| Severity | Package | Version | CVE | Type | Description | Remediation |\n"
                )
                f.write(
                    "|----------|---------|---------|-----|------|-------------|-------------|\n"
                )

                for vuln in vulnerabilities:
                    # CVE link that opens in a new tab
                    cve_link = f"[{vuln['cve']}](https://nvd.nist.gov/vuln/detail/{
                        vuln['cve']
                    })"

                    # Intelligent truncation of the description
                    short_desc = smart_truncate(vuln["description"])

                    # Severity with HTML color
                    color = severity_colors.get(vuln["severity"], "#000000")
                    severity_html = f'<span style="color: {color}; font-weight: bold;">{
                        vuln["severity"]
                    }</span>'

                    f.write(
                        f"| {severity_html} | {vuln['package']} | {vuln['version']} | {
                            cve_link
                        } | {vuln['type']} | {short_desc} | {vuln['remediation']} |\n"
                    )
            else:
                f.write("✅ No vulnerabilities found in dependencies.\n")

            # Code Findings Section - Sorted by risk level
            if code_findings:
                # Colors for each severity level
                risk_colors = {
                    "CRITICAL": "#FF4444",  # Intense red
                    "HIGH": "#FF6B35",  # Reddish orange
                    "MEDIUM": "#FFA500",  # Orange
                    "LOW": "#4CAF50",  # Green
                    "UNKNOWN": "#757575",  # Gray
                }

                # Sort code findings by risk level in order: CRITICAL, HIGH, MEDIUM, LOW
                risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                sorted_findings = sorted(
                    code_findings, key=lambda x: risk_order.get(x["risk"], 4)
                )

                f.write("\n## 🕵️ Suspicious Code Patterns\n\n")
                f.write(
                    "| File | Line | Pattern | Risk | Description | Recommendation |\n"
                )
                f.write(
                    "|------|------|---------|------|-------------|----------------|\n"
                )

                for finding in sorted_findings:
                    # Risk with HTML color
                    color = risk_colors.get(finding["risk"], "#000000")
                    risk_html = f'<span style="color: {color}; font-weight: bold;">{
                        finding["risk"]
                    }</span>'
                    f.write(
                        f"| {finding['file']} | {finding['line']} | {
                            finding['pattern']
                        } | {risk_html} | {finding['description']} | {
                            finding['recommendation']
                        } |\n"
                    )

            f.write("\n## 🔧 Recommendations\n\n")
            f.write("1. Update vulnerable dependencies to patched versions\n")
            f.write("2. Review and fix suspicious code patterns\n")
            f.write("3. Run regular security scans\n")
            f.write("4. Implement secure coding practices\n")

            f.write("\n---\n*Report generated by Tyr Vulnerability Scanner v1.1.0*")

    def run_scan(
        self,
        project_path: str,
        project_name: str = None,
        output_file: str = "tyr_report.md",
        quiet: bool = False,
    ):
        """Run complete security scan"""
        if not quiet:
            self.print_banner()

        project_path = Path(project_path)
        if not project_path.exists():
            print(
                f"{self.colors.RED}Error: Project path {project_path} does not exist{
                    self.colors.END
                }"
            )
            sys.exit(1)

        if not project_name:
            project_name = project_path.name

        if not quiet:
            print(f"🔍 Scanning project: {project_name}")
            print(f"📁 Path: {project_path}")

        # Find and parse dependency files
        dependency_files = self.find_dependency_files(project_path)
        if not quiet:
            print(f"📄 Dependency files found: {len(dependency_files)}")

        dependencies = []
        for file_path in dependency_files:
            deps = self.parse_dependencies(file_path)
            dependencies.extend(deps)

        if not quiet:
            print(f"📦 Dependencies found: {len(dependencies)}")

        # Scan for code patterns if enabled
        code_findings = []
        if self.code_scanner:
            if not quiet:
                print("🕵️ Scanning for suspicious code patterns...")
            code_findings = self.code_scanner.scan_directory(project_path)
            if not quiet:
                print(f"🔍 Suspicious patterns found: {len(code_findings)}")

        # Scan for vulnerabilities
        if not quiet:
            print("🔍 Searching for vulnerabilities...")
            print("📡 Using multiple sources: NVD and OSV")
            if self.nvd_client.api_key:
                print("✅ Using NVD API Key: faster scanning")

        vulnerabilities = self.scan_vulnerabilities(dependencies)

        # Generate report
        self.generate_report(
            vulnerabilities, code_findings, project_name, output_file, str(project_path)
        )

        # Print summary
        if not quiet:
            print(f"🚨 Vulnerabilities found: {len(vulnerabilities)}")
            if self.code_scanner:
                print(f"🕵️ Suspicious patterns found: {len(code_findings)}")
            print(f"📊 Report generated: {output_file}")

            # Vulnerability breakdown
            if vulnerabilities:
                critical = sum(
                    1 for v in vulnerabilities if v["severity"] == "CRITICAL"
                )
                high = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
                medium = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
                low = sum(1 for v in vulnerabilities if v["severity"] == "LOW")

                print("\n📈 Summary:")
                print(f"  CRITICAL: {critical}")
                print(f"  HIGH: {high}")
                print(f"  MEDIUM: {medium}")
                print(f"  LOW: {low}")

            # Code findings breakdown
            if code_findings:
                high_risk = sum(1 for cf in code_findings if cf["risk"] == "HIGH")
                medium_risk = sum(1 for cf in code_findings if cf["risk"] == "MEDIUM")
                low_risk = sum(1 for cf in code_findings if cf["risk"] == "LOW")

                print(f"  SUSPICIOUS: {len(code_findings)}")
                print(f"    HIGH: {high_risk}")
                print(f"    MEDIUM: {medium_risk}")
                print(f"    LOW: {low_risk}")


def main():
    # Print banner when help is requested
    if "-h" in sys.argv or "--help" in sys.argv:
        scanner = TyrScanner()
        scanner.print_banner()

    parser = argparse.ArgumentParser(description="Tyr - Vulnerability Scanner")
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("-n", "--project-name", help="Project name for the report")
    parser.add_argument(
        "-o", "--output", default="tyr_report.md", help="Output filename"
    )
    parser.add_argument("-k", "--nvd-api-key", help="NVD API key for faster scans")
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API requests in seconds",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode (only shows final message)",
    )
    parser.add_argument(
        "-c",
        "--code-scan",
        action="store_true",
        help="Enable suspicious code pattern detection",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="Tyr Vulnerability Scanner v{__version__}",
    )

    args = parser.parse_args()

    scanner = TyrScanner(
        nvd_api_key=args.nvd_api_key, delay=args.delay, enable_code_scan=args.code_scan
    )
    scanner.run_scan(
        project_path=args.project_path,
        project_name=args.project_name,
        output_file=args.output,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()
