# Tyr Plugins

This directory contains plugins for the Tyr security scanner. Tyr supports two types of plugins:

1. **VulnerabilityScanner Plugins** - Query vulnerability databases for known CVEs in dependencies
2. **Analyzer Plugins** - Analyze source code for security issues and code quality

## Available Plugins

### Vulnerability Scanner Plugins

| Plugin | Name | Description | API Key Required |
|--------|------|-------------|------------------|
| `nvd.py` | nvd | National Vulnerability Database (US Government) | Optional |
| `osv.py` | osv | Open Source Vulnerabilities (Google) | No |
| `github_advisory.py` | github-advisory | GitHub Security Advisory Database | Optional |

### Code Analyzer Plugins

| Plugin | Name | Description | Languages |
|--------|------|-------------|-----------|
| `sql_injection_detector.py` | sql-injection | Detects SQL injection vulnerabilities | PHP, JS, Python, Java |
| `xss_detector.py` | xss-detector | Detects XSS (Cross-Site Scripting) | PHP, JS, React, Vue, Python |
| `auth_checker.py` | auth-checker | Detects missing authentication/authorization | Express, PHP, Flask, Django |
| `command_injection_detector.py` | command-injection | Detects command injection risks | PHP, JS, Python, Java, Ruby |
| `csrf_protection_checker.py` | csrf-protection | Detects missing CSRF protection | HTML, Express, Flask, Django |
| `path_traversal_detector.py` | path-traversal | Detects path traversal vulnerabilities | PHP, JS, Python, Java, Go |
| `secrets_scanner.py` | secrets-scanner | Detects hardcoded secrets, API keys | All languages |
| `code_smell_detector.py` | code-smell | Detects code quality issues | All languages |

## Usage

### List All Available Plugins

```bash
python tyr.py --list-plugins
```

### Use Vulnerability Scanner Plugins

Use one plugin:
```bash
python tyr.py /path/to/project --plugins nvd
```

Use multiple plugins (comma-separated):
```bash
python tyr.py /path/to/project --plugins nvd,osv
```

Use all available plugins:
```bash
python tyr.py /path/to/project --plugins all
```

### Use Code Analyzer Plugins

Use specific analyzers:
```bash
python tyr.py /path/to/project --analyzers sql-injection,xss-detector
```

Use all analyzers:
```bash
python tyr.py /path/to/project --analyzers all
```

### Combined Scanning

```bash
# Full security scan
python tyr.py /path/to/project --plugins nvd,osv --analyzers all

# OWASP Top 10 scan
python tyr.py /path/to/project --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal
```

### Analyzer Custom Arguments

Each analyzer supports custom arguments:

```bash
# SQL injection with strict mode
python tyr.py /path --analyzers sql-injection --strict-mode true

# XSS only React patterns
python tyr.py /path --analyzers xss-detector --check-react true --check-dom false

# Secrets with high entropy
python tyr.py /path --analyzers secrets-scanner --min-entropy 5.0

# Code smell with custom thresholds
python tyr.py /path --analyzers code-smell --max-function-lines 30
```

## Plugin Configuration

Some plugins support API keys for better performance:

**NVD Plugin:**
```bash
export NVD_API_KEY="your_api_key_here"
python tyr.py /path/to/project --plugins nvd
```

**GitHub Advisory Plugin:**
```bash
export GITHUB_TOKEN="your_github_token_here"
python tyr.py /path/to/project --plugins github-advisory
```

You can also pass API keys via command line:
```bash
python tyr.py /path/to/project --plugins nvd --nvd-api-key YOUR_KEY
```

## Creating a New Plugin

### Option 1: Vulnerability Scanner Plugin

Create a new Python file in the `plugins/` directory:

```python
"""
My Custom Plugin for Tyr
Description of what your plugin does
"""

import time
from typing import Dict, List, Any
import requests
from plugins.base import VulnerabilityPlugin


class MyCustomPlugin(VulnerabilityPlugin):
    """Plugin for querying My Custom Vulnerability Database"""

    @property
    def name(self) -> str:
        return "my-plugin"

    @property
    def display_name(self) -> str:
        return "My Custom Vulnerability Database"

    @property
    def description(self) -> str:
        return "Custom vulnerability database for specialized scanning"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def requires_api_key(self) -> bool:
        return False

    @property
    def api_key_env_var(self) -> str:
        return "MY_PLUGIN_API_KEY"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.base_url = "https://api.example.com/v1"
        self.delay = kwargs.get("delay", 1.0)

    def is_available(self) -> bool:
        try:
            response = requests.get(self.base_url, timeout=self.timeout)
            return response.status_code in [200, 401]
        except Exception:
            return False

    def query_vulnerabilities(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Query vulnerabilities for a specific package and version.
        
        Returns list of dictionaries with this structure:
        {
            'id': str,              # Vulnerability ID
            'source': str,          # Plugin name
            'description': str,     # Vulnerability description
            'cvss_score': float,   # CVSS score (0.0-10.0)
            'severity': str,        # CRITICAL, HIGH, MEDIUM, LOW
            'references': List[str], # URLs for more info
            'published': str,       # Publication date
            'cwe': List[str],       # CWE identifiers
        }
        """
        vulnerabilities = []
        
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = requests.get(
                f"{self.base_url}/vulnerabilities",
                params={"package": package_name, "version": version},
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            time.sleep(self.delay)
            
            for item in data.get("vulnerabilities", []):
                vulnerability = {
                    "id": item.get("id", ""),
                    "source": self.name,
                    "description": item.get("description", ""),
                    "cvss_score": item.get("cvss_score", 0.0),
                    "severity": item.get("severity", "UNKNOWN"),
                    "references": item.get("references", []),
                    "published": item.get("published_at", ""),
                    "cwe": item.get("cwe_ids", []),
                }
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ {self.display_name} error: {e}")
            return []
```

### Option 2: Code Analyzer Plugin

Create a new Python file in the `plugins/` directory:

```python
"""
My Custom Analyzer Plugin for Tyr
Analyzes source code for security or quality issues
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class MyCustomAnalyzer(AnalyzerPlugin):
    """Analyzer for detecting custom patterns in code"""

    @property
    def name(self) -> str:
        return "my-analyzer"

    @property
    def display_name(self) -> str:
        return "My Custom Analyzer"

    @property
    def description(self) -> str:
        return "Detects custom security or quality patterns"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.ts', '.py', '.php']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'strict-mode': {
                'help': 'Enable strict mode for more detections',
                'type': bool,
                'default': False,
            },
        }

    def is_available(self) -> bool:
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for the custom pattern"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Define patterns to detect
            patterns = [
                {
                    'pattern': r'your_pattern_here',
                    'issue': 'Issue Name',
                    'severity': 'HIGH',
                    'description': 'Description of the issue',
                    'recommendation': 'How to fix it',
                },
            ]
            
            for i, line in enumerate(lines, 1):
                for pattern_info in patterns:
                    if re.search(pattern_info['pattern'], line):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': pattern_info['severity'],
                            'category': 'security',  # or 'quality'
                            'issue': pattern_info['issue'],
                            'message': pattern_info['description'],
                            'recommendation': pattern_info['recommendation'],
                            'code_snippet': line.strip()[:100],
                        })
        
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings
```

## Plugin Architecture

```
plugins/
├── base.py                       # VulnerabilityPlugin base class
├── base_analyzer.py              # AnalyzerPlugin base class
├── nvd.py                       # NVD plugin
├── osv.py                       # OSV plugin
├── github_advisory.py           # GitHub plugin
├── sql_injection_detector.py   # SQL injection analyzer
├── xss_detector.py             # XSS analyzer
├── auth_checker.py             # Auth checker analyzer
├── command_injection_detector.py
├── csrf_protection_checker.py
├── path_traversal_detector.py
├── secrets_scanner.py
├── code_smell_detector.py
└── your_plugin.py              # Your custom plugin
```

## Plugin Lifecycle

### VulnerabilityScanner Plugins
1. **Discovery**: Tyr scans the `plugins/` directory
2. **Loading**: Imports plugin modules and finds `VulnerabilityPlugin` subclasses
3. **Initialization**: Creates plugin instances with configuration
4. **Availability Check**: Calls `is_available()`
5. **Query**: Calls `query_vulnerabilities()` for each dependency
6. **Aggregation**: Combines results from all enabled plugins

### Analyzer Plugins
1. **Discovery**: Tyr scans for `AnalyzerPlugin` subclasses
2. **File Discovery**: Finds source files matching `supported_extensions`
3. **Analysis**: Calls `analyze_file()` for each file
4. **Reporting**: Aggregates findings by severity and category

## Troubleshooting

### Plugin Not Found
- Ensure plugin file is in `plugins/` directory
- Plugin file must end with `.py`
- Plugin class must inherit from correct base class
- Check for syntax errors in plugin code

### Plugin Not Available
- Check `is_available()` implementation
- Verify API endpoint is reachable
- Check API key is set if required
- Review network connectivity

### No Results Found
- Verify patterns are correct
- Check file extensions are in `supported_extensions`
- Ensure you're using the correct plugin/analyzer name
- Add debug output to see what's happening

## Contributing

To contribute a new plugin:

1. Fork the repository
2. Create your plugin in `plugins/` directory
3. Test thoroughly with different projects
4. Update this README with plugin information
5. Submit a pull request

---

For questions or issues with plugins, please open an issue in the repository.
