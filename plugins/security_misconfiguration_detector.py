"""
Security Misconfiguration Detector Plugin for Tyr
Detects security misconfigurations in code
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class SecurityMisconfigurationDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting security misconfigurations"""

    @property
    def name(self) -> str:
        return "security-misconfig"

    @property
    def display_name(self) -> str:
        return "Security Misconfiguration Detector"

    @property
    def description(self) -> str:
        return "Detects security misconfigurations: debug mode, CORS, insecure headers, default credentials"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.env', '.yaml', '.yml', '.json', '.java', '.go']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'check-debug': {
                'help': 'Check for debug mode enabled in production',
                'type': bool,
                'default': True,
            },
            'check-cors': {
                'help': 'Check for insecure CORS configurations',
                'type': bool,
                'default': True,
            },
            'check-headers': {
                'help': 'Check for missing security headers',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for security misconfigurations"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            if ext == '.py':
                findings.extend(self._detect_python_misconfig(file_path, lines, content))
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_misconfig(file_path, lines, content))
            elif ext == '.php':
                findings.extend(self._detect_php_misconfig(file_path, lines, content))
            elif ext in ['.env']:
                findings.extend(self._detect_env_misconfig(file_path, lines))
            elif ext in ['.yaml', '.yml']:
                findings.extend(self._detect_yaml_misconfig(file_path, lines, content))
            elif ext == '.java':
                findings.extend(self._detect_java_misconfig(file_path, lines, content))
            elif ext == '.go':
                findings.extend(self._detect_go_misconfig(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_python_misconfig(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in Python"""
        findings = []
        
        patterns = [
            # Flask debug mode
            {
                'pattern': r'app\.run\s*\([^)]*debug\s*=\s*True',
                'issue': 'Flask Debug Mode Enabled',
                'severity': 'HIGH',
                'description': 'Flask app running with debug=True in code',
                'recommendation': 'Set debug=False in production or use environment variable',
            },
            # Django DEBUG = True
            {
                'pattern': r'DEBUG\s*=\s*True',
                'issue': 'Django DEBUG Mode Enabled',
                'severity': 'HIGH',
                'description': 'Django DEBUG setting is True',
                'recommendation': 'Set DEBUG=False in production settings',
            },
            # Flask secret key hardcoded
            {
                'pattern': r'SECRET_KEY\s*=\s*["\'][^"\']{8,}["\']',
                'issue': 'Hardcoded Flask SECRET_KEY',
                'severity': 'HIGH',
                'description': 'Flask SECRET_KEY is hardcoded in source',
                'recommendation': 'Use environment variable: os.environ.get("SECRET_KEY")',
            },
            # Django secret key hardcoded
            {
                'pattern': r'SECRET_KEY\s*=\s*["\'][^"\']{20,}["\']',
                'issue': 'Hardcoded Django SECRET_KEY',
                'severity': 'HIGH',
                'description': 'Django SECRET_KEY is hardcoded in source',
                'recommendation': 'Use environment variable for SECRET_KEY',
            },
            # SQLALCHEMY_DATABASE_URI with credentials
            {
                'pattern': r'SQLALCHEMY_DATABASE_URI\s*=\s*["\']mysql://[^"\']+:[^"\']+@',
                'issue': 'Database Credentials in URI',
                'severity': 'CRITICAL',
                'description': 'Database connection string contains hardcoded credentials',
                'recommendation': 'Use environment variables for database credentials',
            },
            # Allow subdomain CORS
            {
                'pattern': r'CORS_ALLOW_SUBORIGINS\s*=\s*["\']\*["\']',
                'issue': 'CORS Allows All Subdomains',
                'severity': 'HIGH',
                'description': 'CORS allows all subdomains (*.domain.com)',
                'recommendation': 'Specify exact allowed origins',
            },
            # Flask CORS wildcard
            {
                'pattern': r'CORS_ORIGINS\s*=\s*["\']\*["\']',
                'issue': 'CORS Allows All Origins',
                'severity': 'HIGH',
                'description': 'CORS allows all origins (wildcard *)',
                'recommendation': 'Specify exact allowed origins, never use * in production',
            },
            # SQLAlchemy echo enabled
            {
                'pattern': r'SQLALCHEMY_ECHO\s*=\s*True',
                'issue': 'SQLAlchemy Echo Enabled',
                'severity': 'MEDIUM',
                'description': 'SQLAlchemy echo is enabled, exposes SQL queries',
                'recommendation': 'Set SQLALCHEMY_ECHO=False in production',
            },
            # Session cookie not secure
            {
                'pattern': r'SESSION_COOKIE_SECURE\s*=\s*False',
                'issue': 'Session Cookie Not Secure',
                'severity': 'MEDIUM',
                'description': 'Session cookies are not marked as secure',
                'recommendation': 'Set SESSION_COOKIE_SECURE=True',
            },
            # CORS without credentials
            {
                'pattern': r'CORS_ALLOW_CREDENTIALS\s*=\s*True',
                'issue': 'CORS with Credentials Allowed',
                'severity': 'MEDIUM',
                'description': 'CORS allows credentials with wildcard origin',
                'recommendation': 'Do not use * origin with credentials',
            },
            # Debug toolbar enabled
            {
                'pattern': r'DEBUG_TOOLBAR_CONFIG\s*=\s*\{',
                'issue': 'Debug Toolbar Enabled',
                'severity': 'MEDIUM',
                'description': 'Flask-DebugToolbar is enabled',
                'recommendation': 'Disable debug toolbar in production',
            },
            # Error reporting in production
            {
                'pattern': r'error_reporting\s*\(\s*E_ALL\s*\)',
                'issue': 'Full Error Reporting Enabled',
                'severity': 'MEDIUM',
                'description': 'PHP error reporting set to show all errors',
                'recommendation': 'Use error_reporting(0) in production',
            },
            # Display errors enabled
            {
                'pattern': r'display_errors\s*=\s*(1|On|True)',
                'issue': 'Display Errors Enabled',
                'severity': 'HIGH',
                'description': 'PHP display_errors is enabled',
                'recommendation': 'Set display_errors=0 in production php.ini',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('#'):
                continue
            
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['issue'],
                        'message': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'code_snippet': stripped[:100],
                    })
        
        return findings

    def _detect_javascript_misconfig(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in JavaScript/Node.js"""
        findings = []
        
        patterns = [
            # Express session secret weak
            {
                'pattern': r'express-session.*secret\s*:\s*["\'][^"\']{8,15}["\']',
                'issue': 'Weak Session Secret',
                'severity': 'HIGH',
                'description': 'Express session using short/weak secret',
                'recommendation': 'Use a strong, random secret (32+ characters)',
            },
            # CORS wildcard
            {
                'pattern': r'origin\s*:\s*["\']\*["\']',
                'issue': 'CORS Wildcard Origin',
                'severity': 'HIGH',
                'description': 'CORS allows all origins (wildcard *)',
                'recommendation': 'Specify exact allowed origins, never use * in production',
            },
            # CORS credentials with wildcard
            {
                'pattern': r'origin\s*:\s*["\']\*["\'][^}]*credentials\s*:\s*true',
                'issue': 'CORS with Credentials + Wildcard',
                'severity': 'HIGH',
                'description': 'CORS allows credentials with wildcard origin',
                'recommendation': 'Cannot use * origin with credentials, specify exact origin',
            },
            # Helmet not used
            {
                'pattern': r'app\.use\(helmet\(\)\)',
                'issue': 'Helmet Security Headers Not Configured',
                'severity': 'MEDIUM',
                'description': 'Using helmet() without configuration',
                'recommendation': 'Configure helmet with appropriate settings',
            },
            # No rate limiting
            {
                'pattern': r'express-rate-limit',
                'issue': 'Rate Limiting Not Configured',
                'severity': 'MEDIUM',
                'description': 'express-rate-limit imported but may not be configured',
                'recommendation': 'Configure rate limiting middleware',
            },
            # Cookie without secure
            {
                'pattern': r'cookie\s*:\s*\{[^}]*secure\s*:\s*false',
                'issue': 'Cookie Not Marked Secure',
                'severity': 'MEDIUM',
                'description': 'Cookie not marked as secure',
                'recommendation': 'Set cookie.secure = true in production',
            },
            # Cookie without httpOnly
            {
                'pattern': r'cookie\s*:\s*\{[^}]*httpOnly\s*:\s*false',
                'issue': 'Cookie Not Marked HttpOnly',
                'severity': 'MEDIUM',
                'description': 'Cookie not protected from JavaScript access',
                'recommendation': 'Set cookie.httpOnly = true to prevent XSS access',
            },
            # Disable etag
            {
                'pattern': r'app\.disable\s*\(\s*["\']etag["\']\s*\)',
                'issue': 'ETag Disabled',
                'severity': 'LOW',
                'description': 'ETag disabled which may affect caching',
                'recommendation': 'Keep etag enabled for proper caching',
            },
            # Vue axios withCredentials
            {
                'pattern': r'withCredentials\s*:\s*true',
                'issue': 'Cross-Origin Credentials Enabled',
                'severity': 'MEDIUM',
                'description': 'Axios withCredentials enabled',
                'recommendation': 'Ensure server properly validates CORS',
            },
            # Next.js disabled CSRF
            {
                'pattern': r'csrf\s*:\s*false',
                'issue': 'CSRF Protection Disabled',
                'severity': 'HIGH',
                'description': 'CSRF protection explicitly disabled',
                'recommendation': 'Enable CSRF protection',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['issue'],
                        'message': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'code_snippet': stripped[:100],
                    })
        
        return findings

    def _detect_php_misconfig(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in PHP"""
        findings = []
        
        patterns = [
            # Display errors on
            {
                'pattern': r'ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']1["\']',
                'issue': 'Display Errors Enabled',
                'severity': 'HIGH',
                'description': 'PHP display_errors enabled via ini_set',
                'recommendation': 'Set display_errors=0 in production',
            },
            # Error reporting all
            {
                'pattern': r'error_reporting\s*\(\s*E_ALL\s*\)',
                'issue': 'Full Error Reporting',
                'severity': 'MEDIUM',
                'description': 'PHP error_reporting set to show all errors',
                'recommendation': 'Use error_reporting(0) in production',
            },
            # Session cookie not secure
            {
                'pattern': r'ini_set\s*\(\s*["\']session\.cookie_secure["\']\s*,\s*["\']0["\']',
                'issue': 'Session Cookie Not Secure',
                'severity': 'MEDIUM',
                'description': 'Session cookie not marked as secure',
                'recommendation': 'Set session.cookie_secure=1 in php.ini',
            },
            # Session cookie httpOnly off
            {
                'pattern': r'ini_set\s*\(\s*["\']session\.cookie_httponly["\']\s*,\s*["\']0["\']',
                'issue': 'Session Cookie Not HttpOnly',
                'severity': 'MEDIUM',
                'description': 'Session cookie accessible via JavaScript',
                'recommendation': 'Set session.cookie_httponly=1',
            },
            # Allow url include
            {
                'pattern': r'allow_url_include\s*=\s*1',
                'issue': 'Allow URL Include Enabled',
                'severity': 'HIGH',
                'description': 'PHP allow_url_include is enabled (dangerous)',
                'recommendation': 'Set allow_url_include=0 in php.ini',
            },
            # CORS wildcard
            {
                'pattern': r'header\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\']\*["\']',
                'issue': 'CORS Wildcard Origin',
                'severity': 'HIGH',
                'description': 'CORS allows all origins',
                'recommendation': 'Specify exact allowed origin, never * in production',
            },
            # SQL debug
            {
                'pattern': r'(mysqli_debug|PDO::ATTR_DEBUG)::',
                'issue': 'MySQL Debug Enabled',
                'severity': 'MEDIUM',
                'description': 'MySQL debug mode enabled',
                'recommendation': 'Disable debug in production',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['issue'],
                        'message': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'code_snippet': stripped[:100],
                    })
        
        return findings

    def _detect_env_misconfig(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in .env files"""
        findings = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('#') or not stripped:
                continue
            
            # Check for default/weak passwords in env
            if re.search(r'=\s*(password|passwd|pwd)\s*[:=]', stripped, re.IGNORECASE):
                if not re.search(r'=\s*\$', stripped):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'HIGH',
                        'category': 'security',
                        'issue': 'Default Password in .env',
                        'message': 'Default or weak password found in environment file',
                        'recommendation': 'Use strong, unique passwords and store in secure secrets manager',
                        'code_snippet': stripped[:100],
                    })
            
            # Check for debug=true
            if re.search(r'DEBUG\s*=\s*true', stripped, re.IGNORECASE):
                findings.append({
                    'file': str(file_path),
                    'line': i,
                    'severity': 'HIGH',
                    'category': 'security',
                    'issue': 'Debug Mode Enabled in .env',
                    'message': 'DEBUG=true found in environment file',
                    'recommendation': 'Set DEBUG=false for production',
                    'code_snippet': stripped[:100],
                })
            
            # Check for weak secret keys
            if re.search(r'(SECRET|TOKEN|KEY)\s*=\s*["\']?\w{1,20}["\']?$', stripped, re.IGNORECASE):
                findings.append({
                    'file': str(file_path),
                    'line': i,
                    'severity': 'MEDIUM',
                    'category': 'security',
                    'issue': 'Weak Secret Key in .env',
                    'message': 'Short or weak secret key found',
                    'recommendation': 'Use strong, random keys (32+ characters)',
                    'code_snippet': stripped[:100],
                })
        
        return findings

    def _detect_yaml_misconfig(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in YAML files"""
        findings = []
        
        # Check for debug mode in YAML configs
        if re.search(r'debug:\s*(true|yes|1|on)', content, re.IGNORECASE):
            for i, line in enumerate(lines, 1):
                if re.search(r'debug:\s*(true|yes|1|on)', line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'HIGH',
                        'category': 'security',
                        'issue': 'Debug Mode Enabled in Config',
                        'message': 'Debug mode enabled in YAML configuration',
                        'recommendation': 'Disable debug mode in production',
                        'code_snippet': line.strip()[:100],
                    })
        
        # Check for disabled authentication
        if re.search(r'auth\s*:\s*false', content, re.IGNORECASE):
            for i, line in enumerate(lines, 1):
                if re.search(r'auth\s*:\s*false', line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'HIGH',
                        'category': 'security',
                        'issue': 'Authentication Disabled',
                        'message': 'Authentication explicitly disabled in config',
                        'recommendation': 'Enable authentication in production',
                        'code_snippet': line.strip()[:100],
                    })
        
        # Check for insecure CORS
        if re.search(r'cors.*origin.*["\']\*["\']', content, re.IGNORECASE):
            for i, line in enumerate(lines, 1):
                if re.search(r'origin.*["\']\*["\']', line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'HIGH',
                        'category': 'security',
                        'issue': 'CORS Wildcard Origin',
                        'message': 'CORS allows all origins in config',
                        'recommendation': 'Specify exact allowed origins',
                        'code_snippet': line.strip()[:100],
                    })
        
        return findings

    def _detect_java_misconfig(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in Java"""
        findings = []
        
        patterns = [
            # WebSecurityConfigurerAdapter disabled
            {
                'pattern': r'@EnableWebSecurity',
                'issue': 'Custom WebSecurityConfigurerAdapter',
                'severity': 'MEDIUM',
                'description': 'Custom WebSecurityConfigurerAdapter found',
                'recommendation': 'Ensure proper security configuration',
            },
            # Actuator endpoints exposed
            {
                'pattern': r'management\.endpoints\.web\.exposure\.include\s*=\s*\*',
                'issue': 'Actuator Endpoints Exposed',
                'severity': 'HIGH',
                'description': 'Spring Boot actuator endpoints exposed publicly',
                'recommendation': 'Restrict actuator endpoints or protect with auth',
            },
            # H2 console enabled
            {
                'pattern': r'spring\.h2\.console\.enabled\s*=\s*true',
                'issue': 'H2 Console Enabled',
                'severity': 'HIGH',
                'description': 'H2 database console enabled in production',
                'recommendation': 'Disable H2 console in production',
            },
            # Default credentials
            {
                'pattern': r'spring\.datasource\.password\s*=\s*["\']?password["\']?',
                'issue': 'Default Database Password',
                'severity': 'HIGH',
                'description': 'Default or weak database password in config',
                'recommendation': 'Use strong password and environment variables',
            },
            # Trace enabled
            {
                'pattern': r'server\.error\.include-stacktrace\s*=\s*always',
                'issue': 'Stack Trace Enabled',
                'severity': 'MEDIUM',
                'description': 'Stack traces enabled in error responses',
                'recommendation': 'Set to never or on_param in production',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*'):
                continue
            
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['issue'],
                        'message': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'code_snippet': stripped[:100],
                    })
        
        return findings

    def _detect_go_misconfig(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect security misconfigurations in Go"""
        findings = []
        
        patterns = [
            # CORS wildcard
            {
                'pattern': r'AllowedOrigins\s*:\s*\[\]\s*string\s*\{\s*["\*]+',
                'issue': 'CORS Wildcard Origin',
                'severity': 'HIGH',
                'description': 'CORS allows all origins',
                'recommendation': 'Specify exact allowed origins',
            },
            # Debug enabled
            {
                'pattern': r'"debug"\s*:\s*true',
                'issue': 'Debug Mode Enabled',
                'severity': 'HIGH',
                'description': 'Debug mode enabled',
                'recommendation': 'Disable debug in production',
            },
            # TLS disabled
            {
                'pattern': r'TLSConfig\s*:\s*nil',
                'issue': 'TLS Not Configured',
                'severity': 'HIGH',
                'description': 'TLS not configured for server',
                'recommendation': 'Configure TLS with valid certificates',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//'):
                continue
            
            for pattern_info in patterns:
                if re.search(pattern_info['pattern'], line):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['issue'],
                        'message': pattern_info['description'],
                        'recommendation': pattern_info['recommendation'],
                        'code_snippet': stripped[:100],
                    })
        
        return findings
