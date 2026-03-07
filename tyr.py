#!/usr/bin/env python3
"""
Tyr - Vulnerability Scanner
Security scanner that analyzes projects for vulnerable dependencies and suspicious code patterns.
"""

import argparse
import importlib
import inspect
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

import requests

# Import plugin base classes
try:
    from plugins.base import VulnerabilityPlugin
    from plugins.base_analyzer import AnalyzerPlugin
except ImportError as e:
    print(f"❌ Error: Could not import plugin modules: {e}")
    print("Make sure the plugins/ directory exists and contains base.py and base_analyzer.py")
    sys.exit(1)

__version__ = "1.3.0"


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


class PluginManager:
    """Manages vulnerability scanner plugins and code analyzers"""

    def __init__(self, verbose: bool = False):
        self.plugins: Dict[str, VulnerabilityPlugin] = {}
        self.analyzers: Dict[str, AnalyzerPlugin] = {}
        self.verbose = verbose
        self.colors = Colors()

    def discover_plugins(self):
        """Automatically discover and load plugins from the plugins directory"""
        plugins_dir = Path(__file__).parent / "plugins"

        if not plugins_dir.exists():
            if self.verbose:
                print(f"{self.colors.YELLOW}⚠️  Plugins directory not found: {plugins_dir}{self.colors.END}")
            return

        # Get all Python files in plugins directory (except base files and __init__.py)
        plugin_files = [
            f for f in plugins_dir.glob("*.py")
            if f.name not in ["__init__.py", "base.py", "base_analyzer.py"]
        ]

        for plugin_file in plugin_files:
            try:
                # Import the module
                module_name = f"plugins.{plugin_file.stem}"
                module = importlib.import_module(module_name)

                # Find classes that inherit from VulnerabilityPlugin or AnalyzerPlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a VulnerabilityPlugin
                    if (
                        issubclass(obj, VulnerabilityPlugin)
                        and obj != VulnerabilityPlugin
                        and not issubclass(obj, AnalyzerPlugin)  # Avoid double-loading
                    ):
                        # Instantiate the plugin (without config for now)
                        plugin_instance = obj()
                        self.plugins[plugin_instance.name] = plugin_instance

                        if self.verbose:
                            print(f"{self.colors.GREEN}✅ Loaded vulnerability plugin: {plugin_instance.name}{self.colors.END}")
                    
                    # Check if it's an AnalyzerPlugin
                    elif (
                        issubclass(obj, AnalyzerPlugin)
                        and obj != AnalyzerPlugin
                    ):
                        # Instantiate the analyzer (without config for now)
                        analyzer_instance = obj()
                        self.analyzers[analyzer_instance.name] = analyzer_instance

                        if self.verbose:
                            print(f"{self.colors.GREEN}✅ Loaded analyzer plugin: {analyzer_instance.name}{self.colors.END}")

            except Exception as e:
                if self.verbose:
                    print(f"{self.colors.RED}❌ Failed to load plugin {plugin_file.name}: {e}{self.colors.END}")

    def configure_plugin(self, plugin_name: str, **config):
        """Configure a plugin with specific settings"""
        if plugin_name in self.plugins:
            # Re-instantiate the plugin with configuration
            plugin_class = self.plugins[plugin_name].__class__
            self.plugins[plugin_name] = plugin_class(**config)
    
    def configure_analyzer(self, analyzer_name: str, **config):
        """Configure an analyzer with specific settings"""
        if analyzer_name in self.analyzers:
            # Re-instantiate the analyzer with configuration
            analyzer_class = self.analyzers[analyzer_name].__class__
            self.analyzers[analyzer_name] = analyzer_class(**config)

    def get_plugin(self, name: str) -> VulnerabilityPlugin:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def get_analyzer(self, name: str) -> AnalyzerPlugin:
        """Get an analyzer by name"""
        return self.analyzers.get(name)

    def get_all_plugins(self) -> List[VulnerabilityPlugin]:
        """Get all loaded vulnerability plugins"""
        return list(self.plugins.values())
    
    def get_all_analyzers(self) -> List[AnalyzerPlugin]:
        """Get all loaded analyzers"""
        return list(self.analyzers.values())

    def get_available_plugins(self) -> List[VulnerabilityPlugin]:
        """Get only vulnerability plugins that are available and properly configured"""
        available = []
        for plugin in self.plugins.values():
            if plugin.is_available():
                available.append(plugin)
            elif self.verbose:
                print(f"{self.colors.YELLOW}⚠️  Plugin '{plugin.name}' is not available{self.colors.END}")
        return available
    
    def get_available_analyzers(self) -> List[AnalyzerPlugin]:
        """Get only analyzers that are available"""
        available = []
        for analyzer in self.analyzers.values():
            if analyzer.is_available():
                available.append(analyzer)
            elif self.verbose:
                print(f"{self.colors.YELLOW}⚠️  Analyzer '{analyzer.name}' is not available{self.colors.END}")
        return available

    def list_plugins(self):
        """Display information about all available plugins and analyzers"""
        
        # Display Vulnerability Plugins
        print(f"\n{self.colors.CYAN}{self.colors.BOLD}Vulnerability Scanner Plugins:{self.colors.END}\n")

        if not self.plugins:
            print(f"{self.colors.YELLOW}No vulnerability plugins found.{self.colors.END}\n")
        else:
            print(f"{'Plugin Name':<20} {'Display Name':<35} {'Version':<10} {'Status':<12} {'API Key'}")
            print("-" * 95)

            for plugin in sorted(self.plugins.values(), key=lambda p: p.name):
                # Check availability
                status = f"{self.colors.GREEN}Available{self.colors.END}" if plugin.is_available() else f"{self.colors.RED}Unavailable{self.colors.END}"
                
                # API key requirement
                api_key_info = plugin.api_key_env_var if plugin.requires_api_key else "Not required"
                
                # Check if API key is set
                if plugin.requires_api_key and plugin.api_key_env_var:
                    if os.getenv(plugin.api_key_env_var):
                        api_key_info += f" {self.colors.GREEN}(set){self.colors.END}"
                    else:
                        api_key_info += f" {self.colors.YELLOW}(not set){self.colors.END}"

                print(f"{plugin.name:<20} {plugin.display_name:<35} {plugin.version:<10} {status:<20} {api_key_info}")

            print(f"\n{self.colors.BOLD}Description:{self.colors.END}")
            for plugin in sorted(self.plugins.values(), key=lambda p: p.name):
                print(f"  • {self.colors.CYAN}{plugin.name}{self.colors.END}: {plugin.description}")

            print(f"\n{self.colors.BOLD}Usage:{self.colors.END}")
            print(f"  Use specific plugins:  python tyr.py /path/to/project --plugins nvd,osv")
            print(f"  Use all plugins:       python tyr.py /path/to/project --plugins all")
            print(f"  Default (no --plugins): Uses 'nvd' automatically")
        
        # Display Code Analyzers
        print(f"\n{self.colors.CYAN}{self.colors.BOLD}Code Analyzer Plugins:{self.colors.END}\n")
        
        if not self.analyzers:
            print(f"{self.colors.YELLOW}No analyzer plugins found.{self.colors.END}\n")
        else:
            print(f"{'Analyzer Name':<20} {'Display Name':<35} {'Version':<10} {'Status'}")
            print("-" * 80)
            
            for analyzer in sorted(self.analyzers.values(), key=lambda a: a.name):
                status = f"{self.colors.GREEN}Available{self.colors.END}" if analyzer.is_available() else f"{self.colors.RED}Unavailable{self.colors.END}"
                print(f"{analyzer.name:<20} {analyzer.display_name:<35} {analyzer.version:<10} {status}")
            
            print(f"\n{self.colors.BOLD}Description:{self.colors.END}")
            for analyzer in sorted(self.analyzers.values(), key=lambda a: a.name):
                print(f"  • {self.colors.CYAN}{analyzer.name}{self.colors.END}: {analyzer.description}")
                if analyzer.plugin_arguments:
                    print(f"    {self.colors.BOLD}Arguments:{self.colors.END}")
                    for arg_name, arg_info in analyzer.plugin_arguments.items():
                        default = arg_info.get('default', 'N/A')
                        arg_type = arg_info.get('type', str).__name__
                        print(f"      --{arg_name} ({arg_type}, default: {default})")
            
            print(f"\n{self.colors.BOLD}Usage:{self.colors.END}")
            print(f"  Use specific analyzers: python tyr.py /path/to/project --analyzers code-smell,secrets-scanner")
            print(f"  With custom arguments:  python tyr.py /path/to/project --analyzers code-smell --max-function-lines 30")
        
        print()


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
        """Scan a single file for suspicious patterns"""
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
        """Scan all code files in directory for suspicious patterns"""
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
    """Main vulnerability scanner class with plugin support"""

    def __init__(
        self,
        plugin_names: List[str] = None,
        analyzer_names: List[str] = None,
        nvd_api_key: str = None,
        github_token: str = None,
        delay: float = 1.0,
        enable_code_scan: bool = False,
        verbose: bool = False,
        **analyzer_args  # Custom arguments for analyzers
    ):
        self.colors = Colors()
        self.verbose = verbose
        self.plugin_manager = PluginManager(verbose=verbose)
        self.code_scanner = CodeScanner() if enable_code_scan else None
        
        # Discover all available plugins and analyzers
        self.plugin_manager.discover_plugins()
        
        # Configure plugins with API keys if provided
        if nvd_api_key and "nvd" in self.plugin_manager.plugins:
            self.plugin_manager.configure_plugin("nvd", api_key=nvd_api_key, delay=delay)
        
        if github_token and "github-advisory" in self.plugin_manager.plugins:
            self.plugin_manager.configure_plugin("github-advisory", api_key=github_token, delay=delay)
        
        # Determine which vulnerability plugins to use
        # DEFAULT: Use NVD if no plugins specified
        self.enabled_plugins = []
        if plugin_names is None:
            # Use NVD by default
            if "nvd" in self.plugin_manager.plugins:
                nvd_plugin = self.plugin_manager.get_plugin("nvd")
                if nvd_plugin and nvd_plugin.is_available():
                    self.enabled_plugins.append(nvd_plugin)
                    if verbose:
                        print(f"{self.colors.CYAN}ℹ️  Using NVD plugin by default{self.colors.END}")
        elif plugin_names:
            if "all" in plugin_names:
                self.enabled_plugins = self.plugin_manager.get_available_plugins()
            else:
                for name in plugin_names:
                    plugin = self.plugin_manager.get_plugin(name)
                    if plugin and plugin.is_available():
                        self.enabled_plugins.append(plugin)
                    elif plugin:
                        print(f"{self.colors.YELLOW}⚠️  Plugin '{name}' is not available{self.colors.END}")
                    else:
                        print(f"{self.colors.RED}❌ Plugin '{name}' not found{self.colors.END}")
        
        # Determine which analyzers to use
        self.enabled_analyzers = []
        if analyzer_names:
            if "all" in analyzer_names:
                self.enabled_analyzers = self.plugin_manager.get_available_analyzers()
                # Configure all analyzers with provided arguments
                for analyzer in self.enabled_analyzers:
                    if analyzer_args:
                        self.plugin_manager.configure_analyzer(analyzer.name, verbose=verbose, **analyzer_args)
            else:
                for name in analyzer_names:
                    analyzer = self.plugin_manager.get_analyzer(name)
                    if analyzer and analyzer.is_available():
                        # Configure analyzer with custom arguments
                        if analyzer_args:
                            self.plugin_manager.configure_analyzer(name, verbose=verbose, **analyzer_args)
                            analyzer = self.plugin_manager.get_analyzer(name)  # Get reconfigured instance
                        self.enabled_analyzers.append(analyzer)
                    elif analyzer:
                        print(f"{self.colors.YELLOW}⚠️  Analyzer '{name}' is not available{self.colors.END}")
                    else:
                        print(f"{self.colors.RED}❌ Analyzer '{name}' not found{self.colors.END}")

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
                f"{self.colors.YELLOW}Warning: Could not parse {file_path}: {e}"
                f"{self.colors.END}"
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
        """Scan dependencies for vulnerabilities using enabled plugins"""
        vulnerabilities = []

        if not self.enabled_plugins:
            print(f"{self.colors.YELLOW}ℹ️  No plugins enabled. Use --plugins to enable vulnerability scanning.{self.colors.END}")
            return []

        for dep in dependencies:
            clean_ver = self.clean_version(dep["version"])
            if clean_ver == "unknown":
                continue

            print(f"🔍 Checking {dep['name']} {clean_ver}...")

            # Query all enabled plugins
            seen_ids = set()
            for plugin in self.enabled_plugins:
                try:
                    plugin_vulns = plugin.query_vulnerabilities(
                        dep["name"], clean_ver, dep.get("type")
                    )

                    for vuln in plugin_vulns:
                        vuln_id = vuln.get("id")
                        # Deduplicate by ID
                        if vuln_id and vuln_id not in seen_ids:
                            seen_ids.add(vuln_id)

                            # Ensure required fields
                            vulnerability = {
                                "package": dep["name"],
                                "version": clean_ver,
                                "cve": vuln_id,
                                "source": vuln.get("source", plugin.name),
                                "type": self.determine_vulnerability_type(
                                    vuln.get("description", "")
                                ),
                                "description": vuln.get("description", "No description available"),
                                "cvss_score": vuln.get("cvss_score", 0.0),
                                "severity": vuln.get("severity", "UNKNOWN"),
                                "references": vuln.get("references", []),
                                "remediation": vuln.get("remediation", "Update to a patched version"),
                            }
                            vulnerabilities.append(vulnerability)

                except Exception as e:
                    if self.verbose:
                        print(f"{self.colors.RED}❌ Error with plugin {plugin.name}: {e}{self.colors.END}")

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
            f.write(f"**Project Path:** {project_path}\n")
            
            # Plugin information
            if self.enabled_plugins:
                plugin_names = ", ".join([p.display_name for p in self.enabled_plugins])
                f.write(f"**Plugins Used:** {plugin_names}\n")
            else:
                f.write("**Plugins Used:** None (basic scan only)\n")
            f.write("\n")

            # Vulnerability Summary
            vuln_count = len(vulnerabilities)
            critical_count = sum(
                1 for v in vulnerabilities if v["severity"] == "CRITICAL"
            )
            high_count = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
            medium_count = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
            low_count = sum(1 for v in vulnerabilities if v["severity"] == "LOW")
            unknown_count = sum(
                1
                for v in vulnerabilities
                if v["severity"] not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )

            f.write("## 📊 Executive Summary\n\n")
            f.write(f"- **Total Vulnerabilities:** {vuln_count}\n")
            f.write(f"- **Critical:** {critical_count}\n")
            f.write(f"- **High:** {high_count}\n")
            f.write(f"- **Medium:** {medium_count}\n")
            f.write(f"- **Low:** {low_count}\n")
            if unknown_count > 0:
                f.write(f"- **Unknown:** {unknown_count}\n")

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

                # Sort vulnerabilities by severity
                severity_order = {
                    "CRITICAL": 0,
                    "HIGH": 1,
                    "MEDIUM": 2,
                    "LOW": 3,
                    "UNKNOWN": 4,
                }
                sorted_vulnerabilities = sorted(
                    vulnerabilities, key=lambda x: severity_order.get(x["severity"], 5)
                )

                f.write(
                    "| Severity | Package | Version | CVE | Source | Type | Description | Remediation |\n"
                )
                f.write(
                    "|----------|---------|---------|-----|--------|------|-------------|-------------|\n"
                )

                for vuln in sorted_vulnerabilities:
                    # Dynamic CVE link based on source
                    cve_id = vuln['cve']
                    if cve_id.startswith("CVE-"):
                        cve_link = f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"
                    elif cve_id.startswith("GHSA-"):
                        cve_link = f"[{cve_id}](https://github.com/advisories/{cve_id})"
                    elif vuln["source"] == "osv":
                        cve_link = f"[{cve_id}](https://osv.dev/vulnerability/{cve_id})"
                    else:
                        cve_link = cve_id

                    # Intelligent truncation of the description
                    short_desc = smart_truncate(vuln["description"])

                    # Severity with HTML color
                    color = severity_colors.get(vuln["severity"], "#000000")
                    severity_html = f'<span style="color: {color}; font-weight: bold;">{vuln["severity"]}</span>'

                    f.write(
                        f"| {severity_html} | {vuln['package']} | {vuln['version']} | {cve_link} | {vuln['source']} | {vuln['type']} | {short_desc} | {vuln['remediation']} |\n"
                    )
            else:
                f.write("✅ No vulnerabilities found in dependencies.\n")

            # Code Findings Section
            if code_findings:
                risk_colors = {
                    "CRITICAL": "#FF4444",
                    "HIGH": "#FF6B35",
                    "MEDIUM": "#FFA500",
                    "LOW": "#4CAF50",
                }

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
                    color = risk_colors.get(finding["risk"], "#000000")
                    risk_html = f'<span style="color: {color}; font-weight: bold;">{finding["risk"]}</span>'
                    f.write(
                        f"| {finding['file']} | {finding['line']} | {finding['pattern']} | {risk_html} | {finding['description']} | {finding['recommendation']} |\n"
                    )

            f.write("\n## 🔧 Recommendations\n\n")
            f.write("1. Update vulnerable dependencies to patched versions\n")
            f.write("2. Review and fix suspicious code patterns\n")
            f.write("3. Run regular security scans\n")
            f.write("4. Implement secure coding practices\n")

            f.write(
                f"\n---\n*Report generated by Tyr Vulnerability Scanner v{__version__}*"
            )

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

        project_path_obj = Path(project_path)
        if not project_path_obj.exists():
            print(
                f"{self.colors.RED}Error: Project path {project_path} does not exist{self.colors.END}"
            )
            sys.exit(1)

        if not project_name:
            project_name = project_path_obj.name

        if not quiet:
            print(f"🔍 Scanning project: {project_name}")
            print(f"📁 Path: {project_path}")
            
            if self.enabled_plugins:
                plugin_names = ", ".join([p.name for p in self.enabled_plugins])
                print(f"🔌 Active plugins: {plugin_names}")
            else:
                print(f"🔌 Active plugins: None (use --plugins to enable)")

        # Find and parse dependency files
        dependency_files = self.find_dependency_files(project_path_obj)
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
            code_findings = self.code_scanner.scan_directory(project_path_obj)
            if not quiet:
                print(f"🔍 Suspicious patterns found: {len(code_findings)}")

        # Scan for vulnerabilities using plugins
        if not quiet and self.enabled_plugins:
            print("🔍 Searching for vulnerabilities...")
            print(f"📡 Using plugins: {', '.join([p.display_name for p in self.enabled_plugins])}")

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
                critical_risk = sum(1 for cf in code_findings if cf["risk"] == "CRITICAL")
                high_risk = sum(1 for cf in code_findings if cf["risk"] == "HIGH")
                medium_risk = sum(1 for cf in code_findings if cf["risk"] == "MEDIUM")
                low_risk = sum(1 for cf in code_findings if cf["risk"] == "LOW")

                print(f"\n🕵️ Code Patterns:")
                print(f"  CRITICAL: {critical_risk}")
                print(f"  HIGH: {high_risk}")
                print(f"  MEDIUM: {medium_risk}")
                print(f"  LOW: {low_risk}")


def main():
    parser = argparse.ArgumentParser(
        description="Tyr - Vulnerability Scanner with Plugin Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List available plugins and analyzers:
    python tyr.py --list-plugins

  Basic scan (uses NVD by default):
    python tyr.py /path/to/project

  Scan with specific plugins:
    python tyr.py /path/to/project --plugins nvd,osv

  Scan with all plugins:
    python tyr.py /path/to/project --plugins all

  Use code analyzers:
    python tyr.py /path/to/project --analyzers code-smell,secrets-scanner

  Use analyzers with custom arguments:
    python tyr.py /path/to/project --analyzers code-smell --max-function-lines 30

  Complete scan (plugins + analyzers + code scan):
    python tyr.py /path/to/project --plugins all --analyzers all --code-scan
        """
    )
    
    parser.add_argument("project_path", nargs="?", help="Path to the project to scan")
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List all available plugins and exit"
    )
    parser.add_argument(
        "-p", "--plugins",
        help="Comma-separated list of vulnerability plugins to use (e.g., 'nvd,osv') or 'all'. Default: 'nvd'"
    )
    parser.add_argument(
        "-a", "--analyzers",
        help="Comma-separated list of code analyzers to use (e.g., 'code-smell,secrets-scanner') or 'all'"
    )
    parser.add_argument("-n", "--project-name", help="Project name for the report")
    parser.add_argument(
        "-o", "--output", default="tyr_report.md", help="Output filename"
    )
    parser.add_argument(
        "-k", "--nvd-api-key",
        help="NVD API key for faster scans (or set NVD_API_KEY env var)"
    )
    parser.add_argument(
        "--github-token",
        help="GitHub token for GitHub Advisory plugin (or set GITHUB_TOKEN env var)"
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API requests in seconds (default: 1.0)",
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
        "--verbose",
        action="store_true",
        help="Verbose output (show plugin loading and errors)",
    )
    
    # Analyzer-specific arguments
    parser.add_argument(
        "--max-function-lines",
        type=int,
        help="(code-smell) Maximum lines allowed in a function (default: 50)"
    )
    parser.add_argument(
        "--max-parameters",
        type=int,
        help="(code-smell) Maximum parameters allowed in a function (default: 5)"
    )
    parser.add_argument(
        "--max-nesting",
        type=int,
        help="(code-smell) Maximum nesting depth allowed (default: 4)"
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        help="(secrets-scanner) Minimum entropy for secret detection (default: 4.5)"
    )
    parser.add_argument(
        "--check-entropy",
        type=lambda x: x.lower() in ['true', '1', 'yes'],
        help="(secrets-scanner) Enable high-entropy string detection (default: true)"
    )
    parser.add_argument(
        "--ignore-test-files",
        type=lambda x: x.lower() in ['true', '1', 'yes'],
        help="(secrets-scanner) Ignore files in test directories (default: true)"
    )
    
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"Tyr Vulnerability Scanner v{__version__}",
    )

    args = parser.parse_args()

    # Handle --list-plugins
    if args.list_plugins:
        scanner = TyrScanner(verbose=args.verbose)
        scanner.plugin_manager.list_plugins()
        sys.exit(0)

    # Require project_path if not listing plugins
    if not args.project_path:
        parser.print_help()
        sys.exit(1)

    # Print banner when help is requested
    if "-h" in sys.argv or "--help" in sys.argv:
        scanner = TyrScanner()
        scanner.print_banner()

    # Parse plugin names
    plugin_names = None
    if args.plugins:
        plugin_names = [p.strip() for p in args.plugins.split(",")]
    
    # Parse analyzer names
    analyzer_names = None
    if args.analyzers:
        analyzer_names = [a.strip() for a in args.analyzers.split(",")]

    # Get API keys from args or environment
    nvd_api_key = args.nvd_api_key or os.getenv("NVD_API_KEY")
    github_token = args.github_token or os.getenv("GITHUB_TOKEN")
    
    # Collect analyzer arguments
    analyzer_args = {}
    if args.max_function_lines is not None:
        analyzer_args['max-function-lines'] = args.max_function_lines
    if args.max_parameters is not None:
        analyzer_args['max-parameters'] = args.max_parameters
    if args.max_nesting is not None:
        analyzer_args['max-nesting'] = args.max_nesting
    if args.min_entropy is not None:
        analyzer_args['min-entropy'] = args.min_entropy
    if args.check_entropy is not None:
        analyzer_args['check-entropy'] = args.check_entropy
    if args.ignore_test_files is not None:
        analyzer_args['ignore-test-files'] = args.ignore_test_files

    scanner = TyrScanner(
        plugin_names=plugin_names,
        analyzer_names=analyzer_names,
        nvd_api_key=nvd_api_key,
        github_token=github_token,
        delay=args.delay,
        enable_code_scan=args.code_scan,
        verbose=args.verbose,
        **analyzer_args
    )
    
    scanner.run_scan(
        project_path=args.project_path,
        project_name=args.project_name,
        output_file=args.output,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()
