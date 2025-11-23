# Tyr - Vulnerability Scanner

## 🛡️ What is Tyr?

Tyr is a vulnerability scanner written in Python that analyzes software projects for vulnerable dependencies and suspicious code patterns. Named after the Norse god of war and justice, Tyr aims to protect your projects by identifying potential weak points in dependencies and code.

## ⚡ Key Features

- **🔍 Multi-Source Scanning**: Queries both NVD (National Vulnerability Database) and OSV (Open Source Vulnerabilities) databases
- **🕵️ Code Pattern Detection**: Scans for suspicious code patterns and potential security issues
- **📊 Detailed Reports**: Generates comprehensive HTML-colored reports in Markdown format
- **🚀 Optimized Performance**: Configurable delays and NVD API key support for faster scanning
- **🎯 Accurate Detection**: Identifies vulnerabilities by specific version across multiple package managers
- **🌈 Colorful Interface**: Terminal output with colors for better readability
- **🔗 CVE Links**: Direct links to vulnerability details in NVD database
- **📈 Smart Reporting**: Intelligent text truncation and severity-based coloring

## 📋 Supported Languages and Package Managers

- **JavaScript/Node.js**: `package.json`
- **PHP**: `composer.json`
- **Python**: `requirements.txt`
- **Ruby**: `Gemfile`
- **Java**: `pom.xml`, `build.gradle`
- **Rust**: `Cargo.toml`
- **Docker**: `Dockerfile`

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Dependency Installation

```bash
pip install requests
```

### Script Download

```bash
git clone https://github.com/chrisatdev/tyr.git
cd tyr
```

## 💻 Basic Usage

### Simple Scan

```bash
python3 tyr.py /path/to/your/project
```

### Scan with Custom Project Name

```bash
python3 tyr.py /path/to/your/project -n "My Project"
```

### Scan with NVD API Key (Faster)

```bash
python3 tyr.py /path/to/your/project -k YOUR_NVD_API_KEY
```

### Scan with Code Pattern Detection

```bash
python3 tyr.py /path/to/your/project -c
```

### Quiet Mode (Report Only)

```bash
python3 tyr.py /path/to/your/project -q
```

## 🎯 Command Line Options

| Option               | Description                                          |
| -------------------- | ---------------------------------------------------- |
| `project_path`       | Path to project to scan (required)                   |
| `-n, --project-name` | Project name for report                              |
| `-o, --output`       | Output filename (default: `tyr_report.md`)           |
| `-k, --nvd-api-key`  | NVD API key for faster scans                         |
| `-d, --delay`        | Delay between API requests in seconds (default: 1.0) |
| `-c, --code-scan`    | Enable suspicious code pattern detection             |
| `-q, --quiet`        | Quiet mode (only shows final message)                |
| `-h, --help`         | Show help and exit                                   |
| `-v, --version`      | Show version and exit                                |

## 🔑 Obtaining NVD API Key

To get an NVD API key for faster scanning:

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Register on the portal
3. Request your free API key
4. Use it with the `-k` parameter

**Note**: With API key the delay between requests is 0.6s, without API key it's 6s.

## 📊 Example Output

### Terminal

```
╔══════════════════════════════════════════╗
║                                          ║
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v1.1.0          ║
║          by Christian Benitez            ║
║         cbenitezdiaz@gmail.com           ║
║                                          ║
╚══════════════════════════════════════════╝

Tyr - Vulnerability Scanner v1.1.0
==================================================
🔍 Scanning project: my-project
📁 Path: /path/to/my-project
📄 Dependency files found: 3
📦 Dependencies found: 15
🕵️ Code pattern scanning: Enabled

🔍 Searching for vulnerabilities...
📡 Using multiple sources: NVD and OSV
✅ Using NVD API Key: faster scanning

🚨 Vulnerabilities found: 2
🕵️ Suspicious patterns found: 3
📊 Report generated: tyr_report.md

📈 Summary:
  CRITICAL: 1
  HIGH: 1
  MEDIUM: 1
  LOW: 0

🕵️ Suspicious patterns:
  HIGH: 1
  MEDIUM: 2
  LOW: 0
```

### Generated Markdown Report

The script generates a comprehensive Markdown report with:

- **Executive Summary**: Overview of vulnerabilities and code findings
- **Vulnerability Table**: Color-coded severity levels with direct CVE links
- **Code Pattern Findings**: Detailed suspicious code patterns with risk levels
- **Recommendations**: Actionable security improvement suggestions

## 🛠️ Project Structure

```
tyr/
├── tyr.py              # Main scanner script
├── README.md           # This documentation
├── es/README.md        # This documentation in Spanish
├── tyr_report.md       # Example generated report
```

## 🔧 Development

### Code Structure

- **NVDClient**: Client for interacting with NVD API
- **OSVClient**: Client for Open Source Vulnerabilities database
- **CodeScanner**: Class for suspicious code pattern detection
- **Colors**: Terminal color handling utilities
- **Parser Functions**: For different dependency file types
- **Report Generator**: Creates colored Markdown format reports

### Core Components

- **Multi-Source Scanning**: Queries both NVD and OSV databases for comprehensive coverage
- **Pattern Detection**: Regex-based detection of common security anti-patterns
- **Smart Reporting**: Intelligent text processing and HTML-colored output
- **Error Handling**: Robust error handling with informative messages

## 📝 License

This project is under the MIT License. See the `LICENSE` file for details.

## 🤝 Contributions

Contributions are welcome. Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Limitations

- Scanning depends on NVD and OSV API availability
- Without NVD API key, the process may be slow for projects with many dependencies
- Version vulnerability detection might have false positives/negatives
- Code pattern detection is based on basic pattern matching

## 🆘 Support

If you encounter any issues:

1. Check that you have the latest version
2. Verify that your NVD API key is valid (if using one)
3. Open an issue in the repository with:
   - Problem description
   - Command executed
   - Error output
   - Operating system and Python version

---

**Developed by Christian Benitez** - Questions? Open an issue in the repository.
