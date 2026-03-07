# Tyr - Vulnerability & Security Scanner

## 🛡️ What is Tyr?

Tyr is a comprehensive security scanner written in Python that analyzes software projects for:
- **Vulnerable dependencies** using NVD, OSV, and GitHub Advisory databases
- **Security vulnerabilities** in source code (SQL Injection, XSS, Command Injection, etc.)
- **Code quality issues** (code smells, secrets hardcoded, etc.)

Named after the Norse god of war and justice, Tyr aims to protect your projects by identifying potential security weaknesses.

## ⚡ Key Features

- **🔌 Dual Plugin System**: Extensible architecture like nmap for vulnerability scanners AND code analyzers
- **🔍 Multi-Source Scanning**: Built-in plugins for NVD, OSV, and GitHub Security Advisory databases
- **🛡️ Security Code Analysis**: 8 built-in analyzers for detecting OWASP Top 10 vulnerabilities
- **🎯 Code Analyzers**: Detect SQLi, XSS, Command Injection, CSRF, Path Traversal, Auth issues, Secrets, Code Smells
- **📊 Detailed Reports**: Generates comprehensive colored Markdown reports
- **🚀 Optimized Performance**: Configurable delays and API key support for faster scanning
- **🌈 Colorful Interface**: Terminal output with colors for better readability
- **🔗 CVE Links**: Direct links to vulnerability details in multiple databases
- **⚙️ Flexible Configuration**: Enable/disable specific analyzers with custom arguments
- **💰 100% Free**: No paid APIs required - all features work without API keys

## 📋 Supported Languages

### Package Managers (Dependency Scanning)
- **JavaScript/Node.js**: `package.json`
- **PHP**: `composer.json`
- **Python**: `requirements.txt`, `pyproject.toml`
- **Ruby**: `Gemfile`
- **Java**: `pom.xml`, `build.gradle`
- **Rust**: `Cargo.toml`
- **Go**: `go.mod`

### Source Code Analysis
- **PHP**: Full support for all security patterns
- **JavaScript/Node.js**: Express, Hono, Next.js, React
- **Python**: Flask, Django
- **Java**: Spring, servlets
- **Ruby**: Rails
- **Go**: Standard library

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Dependency Installation

```bash
pip install requests
```

### Quick Start

```bash
git clone https://github.com/chrisatdev/tyr.git
cd tyr
python3 tyr.py --list-plugins
```

## 💻 Usage

### 1. List Available Plugins

```bash
python3 tyr.py --list-plugins
```

### 2. Dependency Vulnerability Scanning

```bash
# Use specific vulnerability scanner plugins
python3 tyr.py /path/to/project --plugins nvd

# Use multiple plugins
python3 tyr.py /path/to/project --plugins nvd,osv

# Use all vulnerability scanners
python3 tyr.py /path/to/project --plugins all
```

### 3. Code Security Analysis (NEW!)

```bash
# Use specific code analyzers
python3 tyr.py /path/to/project --analyzers sql-injection,xss-detector

# Use all security analyzers (recommended for full scan)
python3 tyr.py /path/to/project --analyzers all

# Use specific analyzer with custom arguments
python3 tyr.py /path/to/project --analyzers sql-injection --strict-mode true
```

### 4. Combined Scanning (Vulnerabilities + Code Security)

```bash
# Full security scan
python3 tyr.py /path/to/project --plugins nvd,osv --analyzers all

# OWASP Top 10 scan
python3 tyr.py /path/to/project --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal
```

### 5. With API Keys (Faster)

```bash
# Using command line
python3 tyr.py /path/to/project --plugins nvd -k YOUR_NVD_API_KEY

# Using environment variables
export NVD_API_KEY="your_key_here"
export GITHUB_TOKEN="your_token_here"
python3 tyr.py /path/to/project --plugins nvd,github-advisory
```

### 6. Custom Project Name and Output

```bash
python3 tyr.py /path/to/project --plugins nvd,osv --analyzers all -n "My Project" -o my_report.md
```

## 🎯 Command Line Options

| Option | Description |
|--------|-------------|
| `project_path` | Path to project to scan (required) |
| `--list-plugins` | List all available plugins and exit |
| `-p, --plugins` | Comma-separated vulnerability plugins: nvd, osv, github-advisory, all |
| `-a, --analyzers` | Comma-separated code analyzers or 'all' |
| `-n, --project-name` | Project name for report |
| `-o, --output` | Output filename (default: `tyr_report.md`) |
| `-k, --nvd-api-key` | NVD API key for faster scans |
| `--github-token` | GitHub token for GitHub Advisory plugin |
| `-d, --delay` | Delay between API requests (default: 1.0) |
| `-q, --quiet` | Quiet mode (only shows final message) |
| `--verbose` | Verbose output |
| `-h, --help` | Show help |
| `-v, --version` | Show version |

## 🛡️ Available Security Plugins

### Vulnerability Scanners (Dependency Analysis)

| Plugin | Description | API Key |
|--------|-------------|---------|
| `nvd` | National Vulnerability Database (US Government) | Optional |
| `osv` | Open Source Vulnerabilities (Google) | Not required |
| `github-advisory` | GitHub Security Advisory Database | Optional |

### Code Analyzers (Source Code Analysis)

| Analyzer | Description | Languages |
|----------|-------------|-----------|
| `sql-injection` | Detects SQL injection vulnerabilities | PHP, JS, Python, Java |
| `xss-detector` | Detects XSS (Cross-Site Scripting) | PHP, JS, React, Vue, Python |
| `auth-checker` | Detects missing authentication/authorization | Express, PHP, Flask, Django |
| `command-injection` | Detects command injection risks | PHP, JS, Python, Java, Ruby |
| `csrf-protection` | Detects missing CSRF protection | HTML, Express, Flask, Django |
| `path-traversal` | Detects path traversal vulnerabilities | PHP, JS, Python, Java, Go |
| `secrets-scanner` | Detects hardcoded secrets, API keys, tokens | All languages |
| `code-smell` | Detects code quality issues | All languages |

### Code Analyzer Arguments

Each analyzer supports custom arguments:

```bash
# SQL Injection with strict mode
python3 tyr.py /path --analyzers sql-injection --strict-mode true

# XSS only React patterns
python3 tyr.py /path --analyzers xss-detector --check-react true --check-dom false

# Auth checker with custom critical endpoints
python3 tyr.py /path --analyzers auth-checker --critical-endpoints "delete,admin,payment"

# Secrets scanner with entropy detection
python3 tyr.py /path --analyzers secrets-scanner --min-entropy 4.5 --check-entropy true

# Code smell detector
python3 tyr.py /path --analyzers code-smell --max-function-lines 30 --max-parameters 3
```

## 📊 OWASP Top 10 Coverage

Tyr covers the most critical security risks:

| OWASP Category | Analyzer(s) |
|----------------|-------------|
| A01:2021 - Broken Access Control | path-traversal, csrf-protection, auth-checker |
| A02:2021 - Cryptographic Failures | secrets-scanner, auth-checker |
| A03:2021 - Injection | sql-injection, xss-detector, command-injection |
| A05:2021 - Security Misconfiguration | secrets-scanner |
| A07:2021 - Authentication Failures | auth-checker, secrets-scanner |

## 💰 Free vs Paid Tools Comparison

| Feature | Tyr | SonarQube | Snyk | Veracode |
|---------|-----|-----------|------|----------|
| SQL Injection Detection | ✅ | ✅ | ✅ | ✅ |
| XSS Detection | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ |
| CSRF Protection | ✅ | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ | ✅ |
| Auth Checks | ✅ | ✅ | ✅ | ✅ |
| Secrets Detection | ✅ | ✅ | ✅ | ✅ |
| **Monthly Cost** | **$0** | **$150+** | **$99+** | **$2000+** |
| No API Keys Required | ✅ | ❌ | ❌ | ❌ |
| Local Analysis | ✅ | Partial | ❌ | ❌ |

**Annual Savings: $1,188 - $24,000+**

## 🔑 Obtaining API Keys

### NVD API Key (Optional)

Get faster scanning (0.6s delay vs 6s without):

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Register and request your free API key
3. Use with `-k YOUR_KEY` or set `NVD_API_KEY` environment variable

### GitHub Token (Optional)

For higher rate limits on GitHub Advisory:

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (no special scopes needed)
3. Use with `--github-token` or set `GITHUB_TOKEN` env var

## 📊 Example Output

```
╔══════════════════════════════════════════╗
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v1.3.0          ║
║          by Christian Benitez            ║
║                                          ║
╚══════════════════════════════════════════╝

Tyr - Security Scanner v1.3.0
==================================================
🔍 Scanning project: my-project
📁 Path: /path/to/my-project

📦 Dependency Scanning:
   • Package files: 3 (package.json, requirements.txt, composer.json)
   • Total dependencies: 25

🔍 Code Analysis:
   • Analyzers: sql-injection, xss-detector, auth-checker, command-injection, csrf-protection, path-traversal, secrets-scanner

🔍 Searching vulnerabilities...
📡 Using sources: NVD, OSV, GitHub Advisory
✅ Using NVD API Key: faster scanning

📊 Results:
   Vulnerabilities found: 3
   Code issues found: 12

📈 Summary:
   CRITICAL: 2
   HIGH: 5
   MEDIUM: 6
   LOW: 2

📊 Report generated: tyr_report.md
```

## 🛠️ Project Structure

```
tyr/
├── tyr.py                      # Main scanner script
├── plugins/                    # Plugin directory
│   ├── base.py                 # VulnerabilityPlugin base class
│   ├── base_analyzer.py        # AnalyzerPlugin base class
│   ├── nvd.py                 # NVD vulnerability plugin
│   ├── osv.py                 # OSV vulnerability plugin
│   ├── github_advisory.py      # GitHub Advisory plugin
│   ├── sql_injection_detector.py
│   ├── xss_detector.py
│   ├── auth_checker.py
│   ├── command_injection_detector.py
│   ├── csrf_protection_checker.py
│   ├── path_traversal_detector.py
│   ├── secrets_scanner.py
│   ├── code_smell_detector.py
│   └── README.md              # Plugin development guide
├── es/                        # Spanish documentation
│   └── README.md
├── README.md                  # This documentation
└── tyr_report.md             # Example generated report
```

## 🔧 Creating Custom Plugins

### Vulnerability Plugin (for dependency scanning)

```python
from plugins.base import VulnerabilityPlugin

class MyPlugin(VulnerabilityPlugin):
    @property
    def name(self) -> str:
        return "my-plugin"
    
    @property
    def display_name(self) -> str:
        return "My Custom Plugin"
    
    def is_available(self) -> bool:
        return True
    
    def query_vulnerabilities(self, package_name, package_version, package_type):
        # Implement vulnerability lookup
        return []
```

### Code Analyzer Plugin (for source code scanning)

```python
from plugins.base_analyzer import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    @property
    def name(self) -> str:
        return "my-analyzer"
    
    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.ts']
    
    def analyze_file(self, file_path: Path) -> List[Dict]:
        # Implement code analysis
        return []
```

See [`plugins/README.md`](plugins/README.md) for complete guide.

## 📝 License

This project is under the MIT License. See the `LICENSE` file for details.

## 🤝 Contributions

Contributions are welcome:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Limitations

- Vulnerability scanning depends on NVD/OSV/GitHub API availability
- Without NVD API key, scanning may be slow for large projects
- Code analysis uses pattern matching - may have false positives/negatives

## 🆘 Support

If you encounter issues:

1. Check you have the latest version
2. Verify your API keys are valid (if using)
3. Open an issue with problem description, command, error output, OS and Python version

---

**Developed by Christian Benitez** - Questions? Open an issue in the repository.

**Version:** 1.3.0  
**Date:** 2026-03-06
