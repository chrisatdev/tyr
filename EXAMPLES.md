# Tyr - Usage Examples

This document provides practical examples for using Tyr security scanner.

## Quick Start

### 1. List All Available Plugins

```bash
python3 tyr.py --list-plugins
```

This shows all vulnerability scanners and code analyzers with their arguments.

---

## Basic Scanning Examples

### 2. Scan Dependencies Only (No Code Analysis)

```bash
# Use NVD (default if no --plugins specified)
python3 tyr.py /path/to/project

# Explicitly use NVD
python3 tyr.py /path/to/project --plugins nvd

# Use multiple vulnerability sources
python3 tyr.py /path/to/project --plugins nvd,osv

# Use all vulnerability sources
python3 tyr.py /path/to/project --plugins all
```

### 3. Code Security Analysis Only

```bash
# Scan for SQL injection and XSS
python3 tyr.py /path/to/project --analyzers sql-injection,xss-detector

# Use all security analyzers
python3 tyr.py /path/to/project --analyzers all

# Use specific analyzer with custom arguments
python3 tyr.py /path/to/project --analyzers secrets-scanner --min-entropy 4.5
```

### 4. Full Security Scan (Recommended)

```bash
# Combined: vulnerabilities + code security
python3 tyr.py /path/to/project --plugins nvd,osv --analyzers all

# With custom output filename
python3 tyr.py /path/to/project --plugins all --analyzers all -o security-report.md

# With project name
python3 tyr.py /path/to/project --plugins all --analyzers all -n "My Project" -o report.md
```

---

## OWASP Top 10 Scanning

### 5. Scan for OWASP Top 10 Vulnerabilities

```bash
python3 tyr.py /path/to/project \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal
```

This covers:
- **A01 - Broken Access Control**: path-traversal, csrf-protection, auth-checker
- **A03 - Injection**: sql-injection, xss-detector, command-injection
- **A07 - Auth Failures**: auth-checker

---

## Language-Specific Examples

### 6. PHP Project Scanning

```bash
# Full security scan for PHP
python3 tyr.py /var/www/myapp \
  --plugins nvd \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal,secrets-scanner \
  -n "My PHP App" \
  -o php-security-report.md

# PHP with strict mode
python3 tyr.py /var/www/myapp \
  --analyzers sql-injection --strict-mode true \
  --analyzers xss-detector --check-react false
```

### 7. Node.js/Express Project Scanning

```bash
# Full scan for Express/Node.js
python3 tyr.py /my-node-app \
  --plugins nvd,osv \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,path-traversal \
  -n "Node.js App"

# Next.js specific
python3 tyr.py /nextjs-app \
  --analyzers xss-detector,auth-checker,csrf-protection \
  --check-react true
```

### 8. Python/Flask Project Scanning

```bash
# Full scan for Flask
python3 tyr.py /flask-app \
  --plugins nvd \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,path-traversal \
  -n "Flask App"

# Django specific
python3 tyr.py /django-app \
  --analyzers sql-injection --check-orm true \
  --analyzers xss-detector
```

---

## Advanced Examples

### 9. Using API Keys for Faster Scanning

```bash
# With NVD API key (recommended)
python3 tyr.py /path/to/project --plugins nvd -k YOUR_NVD_API_KEY

# With GitHub token
python3 tyr.py /path/to/project --plugins github-advisory --github-token YOUR_TOKEN

# With both (fastest)
python3 tyr.py /path/to/project \
  --plugins nvd,github-advisory \
  -k YOUR_NVD_API_KEY \
  --github-token YOUR_TOKEN

# Using environment variables
export NVD_API_KEY="your_key"
export GITHUB_TOKEN="your_token"
python3 tyr.py /path/to/project --plugins nvd,github-advisory
```

### 10. Custom Analyzer Arguments

```bash
# SQL injection with strict mode (more detections)
python3 tyr.py /path --analyzers sql-injection --strict-mode true

# XSS only React patterns
python3 tyr.py /path --analyzers xss-detector --check-react true --check-dom false

# Auth checker with custom critical endpoints
python3 tyr.py /path --analyzers auth-checker --critical-endpoints "delete,admin,payment,transfer"

# Secrets scanner with high entropy threshold
python3 tyr.py /path --analyzers secrets-scanner --min-entropy 5.0 --check-entropy true

# Code smell detector with custom thresholds
python3 tyr.py /path --analyzers code-smell --max-function-lines 30 --max-parameters 3

# CSRF checker with custom HTTP methods
python3 tyr.py /path --analyzers csrf-protection --critical-methods "POST,PUT,DELETE,PATCH"
```

### 11. Quiet and Verbose Modes

```bash
# Quiet mode (only final summary)
python3 tyr.py /path/to/project --plugins all --analyzers all -q

# Verbose mode (detailed output)
python3 tyr.py /path/to/project --plugins all --analyzers all --verbose

# With custom delay (for rate limiting)
python3 tyr.py /path/to/project --plugins nvd -d 2.0
```

---

## CI/CD Integration Examples

### 12. GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install requests
        
      - name: Run Tyr Security Scan
        run: |
          python tyr.py . \
            --plugins nvd,osv \
            --analyzers all \
            -o security-report.md
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.md
```

### 13. GitLab CI

```yaml
stages:
  - security

tyr-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install requests
  script:
    - python tyr.py . --plugins nvd,osv --analyzers all -o security-report.md
  artifacts:
    paths:
      - security-report.md
```

### 14. Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install requests'
                sh 'python tyr.py . --plugins nvd,osv --analyzers all -o security-report.md'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts 'security-report.md'
        }
    }
}
```

---

## Real-World Examples

### 15. Scanning a Production PHP Application

```bash
python tyr.py /var/www/html/globalfitness \
  --plugins nvd,osv \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal,secrets-scanner \
  -n "GlobalFitness Production" \
  -o ./reports/globalfitness.md \
  --verbose
```

### 16. Scanning a Node.js API

```bash
python tyr.py ./backend-api \
  --plugins nvd \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,path-traversal \
  -n "Backend API" \
  -o ./reports/backend-api.md \
  --check-react false
```

### 17. Quick Security Check (OWASP Top 10)

```bash
# Fast scan for critical vulnerabilities
python tyr.py /project \
  --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal \
  -n "Quick Scan" \
  -o quick-scan.md \
  -q
```

---

## Output Examples

### Generated Report Structure

The report includes:

1. **Executive Summary**
2. **Vulnerability Findings** (with CVE links)
3. **Code Security Issues** (by analyzer)
4. **Recommendations**

Example section:

```markdown
## SQL Injection Detection

### Findings: 3

| File | Line | Severity | Issue |
|------|------|----------|-------|
| src/users.php | 45 | CRITICAL | User Input in SQL Query |
| api/db.js | 23 | HIGH | String Concatenation in Query |

### Details

**src/users.php:45**
- Severity: CRITICAL
- Issue: User Input in SQL Query
- Code: `$query = "SELECT * FROM users WHERE id = " . $_GET['id'];`
- Recommendation: Use prepared statements with bound parameters
```

---

## Tips and Best Practices

1. **Use API keys** for faster scanning (NVD API key + GitHub token)
2. **Run full scans** (`--plugins all --analyzers all`) periodically
3. **Use OWASP Top 10** scan for quick critical checks
4. **Customize analyzer arguments** based on your project needs
5. **Integrate into CI/CD** for automated security scanning
6. **Review reports** and fix issues by severity (CRITICAL → HIGH → MEDIUM → LOW)

---

## Common Commands Reference

```bash
# List plugins
python tyr.py --list-plugins

# Quick check
python tyr.py /path --analyzers sql-injection,xss-detector

# Full scan
python tyr.py /path --plugins all --analyzers all -o report.md

# With API key
python tyr.py /path --plugins nvd -k YOUR_KEY

# Quiet mode
python tyr.py /path --analyzers all -q
```

---

For more information, see README.md or run `python tyr.py --help`
