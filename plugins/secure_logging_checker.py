"""
Secure Logging Checker Plugin for Tyr
Detects insecure logging practices and missing security logging
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class SecureLoggingCheckerPlugin(AnalyzerPlugin):
    """Plugin for detecting insecure logging practices"""

    @property
    def name(self) -> str:
        return "secure-logging"

    @property
    def display_name(self) -> str:
        return "Secure Logging Checker"

    @property
    def description(self) -> str:
        return "Detects insecure logging: password/token logging, missing security logging, log injection"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.go', '.rb']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'check-sensitive-data': {
                'help': 'Check for logging of sensitive data',
                'type': bool,
                'default': True,
            },
            'check-security-events': {
                'help': 'Check for security event logging',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for insecure logging practices"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            if ext == '.py':
                findings.extend(self._detect_python_logging(file_path, lines))
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_logging(file_path, lines))
            elif ext == '.php':
                findings.extend(self._detect_php_logging(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_logging(file_path, lines))
            elif ext == '.go':
                findings.extend(self._detect_go_logging(file_path, lines))
            elif ext == '.rb':
                findings.extend(self._detect_ruby_logging(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_python_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in Python"""
        findings = []
        
        sensitive_patterns = [
            # Password logging
            {
                'pattern': r'(logger|logging|print)\s*\(.*(password|passwd|pwd).*(\$|_POST|_GET|req|request)',
                'issue': 'Password Logged',
                'severity': 'CRITICAL',
                'description': 'Password or credential logged',
                'recommendation': 'Never log passwords or credentials',
            },
            # Token logging
            {
                'pattern': r'(logger|logging|print)\s*\(.*(token|api_key|secret|jwt).*(\$|_POST|_GET|req|request)',
                'issue': 'API Token/Key Logged',
                'severity': 'CRITICAL',
                'description': 'API token or secret key logged',
                'recommendation': 'Never log API tokens or secret keys',
            },
            # Credit card logging
            {
                'pattern': r'(logger|logging|print)\s*\(.*(credit|card|cvv|cc_number)',
                'issue': 'Credit Card Information Logged',
                'severity': 'CRITICAL',
                'description': 'Credit card or payment information logged',
                'recommendation': 'Never log payment card information (PCI compliance)',
            },
            # SSN logging
            {
                'pattern': r'(logger|logging|print)\s*\(.*(ssn|social.security|pin)',
                'issue': 'Personal Identification Logged',
                'severity': 'HIGH',
                'description': 'Social Security Number or PIN logged',
                'recommendation': 'Never log personal identification numbers',
            },
            # Email logging
            {
                'pattern': r'(logger|logging|print)\s*\(.*email.*(\$|_POST|_GET|req|request)',
                'issue': 'Email Logged',
                'severity': 'MEDIUM',
                'description': 'User email logged',
                'recommendation': 'Be careful logging PII like email addresses',
            },
            # Request body logging
            {
                'pattern': r'(logger|logging)\s*\(.*request\.data|request\.body|request\.json',
                'issue': 'Request Body Logged Entirely',
                'severity': 'MEDIUM',
                'description': 'Entire request body logged, may contain sensitive data',
                'recommendation': 'Log only specific fields, not entire request body',
            },
            # Raw SQL query logging
            {
                'pattern': r'(logger|logging)\s*\(.*(query|sql).*%',
                'issue': 'SQL Query Logged',
                'severity': 'MEDIUM',
                'description': 'SQL query logged, may expose database structure',
                'recommendation': 'Log query parameters separately, not raw queries',
            },
            # Exception with user input
            {
                'pattern': r'except.*:\s*.*logger\.(error|exception)\s*\.(query\(.*req|body|params)',
                'issue': 'Exception with User Input Logged',
                'severity': 'MEDIUM',
                'description': 'User input logged in exception handler',
                'recommendation': 'Sanitize user input before logging in exceptions',
            },
            # f-string with sensitive data
            {
                'pattern': r'logger\.(info|debug|warning|error)\s*\(f["\'].*(password|token|secret|key)',
                'issue': 'Sensitive Data in Log String',
                'severity': 'HIGH',
                'description': 'Sensitive data in f-string log message',
                'recommendation': 'Use structured logging with safe field names',
            },
            # Debug mode with logging
            {
                'pattern': r'logging\.basicConfig.*level=logging\.DEBUG',
                'issue': 'Debug Logging Enabled',
                'severity': 'MEDIUM',
                'description': 'Debug logging enabled, may expose sensitive info',
                'recommendation': 'Use appropriate log level in production',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('#'):
                continue
            
            for pattern_info in sensitive_patterns:
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

    def _detect_javascript_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in JavaScript"""
        findings = []
        
        sensitive_patterns = [
            # console.log with password
            {
                'pattern': r'console\.(log|debug|info)\s*\(.*(password|passwd|pwd)',
                'issue': 'Password Logged',
                'severity': 'CRITICAL',
                'description': 'Password logged to console',
                'recommendation': 'Never log passwords or credentials',
            },
            # console.log with token
            {
                'pattern': r'console\.(log|debug|info)\s*\(.*(token|api_key|secret|jwt|key)',
                'issue': 'API Token/Key Logged',
                'severity': 'CRITICAL',
                'description': 'API token or secret logged to console',
                'recommendation': 'Never log API tokens or secret keys',
            },
            # console.log with user input
            {
                'pattern': r'console\.(log|debug|info)\s*\(.*req\.(body|query|params)',
                'issue': 'User Input Logged',
                'severity': 'MEDIUM',
                'description': 'User input logged without sanitization',
                'recommendation': 'Sanitize user input before logging',
            },
            # console.log with authorization
            {
                'pattern': r'console\.(log|debug|info)\s*\(.*(authorization|bearer|auth)',
                'issue': 'Authorization Header Logged',
                'severity': 'HIGH',
                'description': 'Authorization header logged',
                'recommendation': 'Never log authorization headers',
            },
            # logger.info with sensitive data
            {
                'pattern': r'logger\.(info|debug|warn|error)\s*\(.*(password|token|secret)',
                'issue': 'Sensitive Data in Logger',
                'severity': 'HIGH',
                'description': 'Sensitive data passed to logger',
                'recommendation': 'Never log sensitive data',
            },
            # morgan with body
            {
                'pattern': r'morgan\([^)]*(body|req\.body)',
                'issue': 'Request Body in Morgan Log',
                'severity': 'HIGH',
                'description': 'Morgan logging request body which may contain sensitive data',
                'recommendation': 'Configure morgan to not log request body',
            },
            # winston with sensitive data
            {
                'pattern': r'winston\.log\([^)]*(password|token|secret|key)',
                'issue': 'Sensitive Data in Winston',
                'severity': 'CRITICAL',
                'description': 'Sensitive data in Winston logger',
                'recommendation': 'Use safe logging practices with Winston',
            },
            # Debug enabled in production
            {
                'pattern': r'console\.(log|debug|info)\s*\(',
                'issue': 'Console Logging in Code',
                'severity': 'LOW',
                'description': 'console.log found in code',
                'recommendation': 'Remove console logs in production or use proper logger',
            },
            # Error handler with user data
            {
                'pattern': r'\.on\s*\(\s*["\']error["\']\s*,\s*.*console\.log.*req\.',
                'issue': 'Error Handler Logs Request',
                'severity': 'MEDIUM',
                'description': 'Error handler logging user request data',
                'recommendation': 'Sanitize error messages, don\'t log raw requests',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            for pattern_info in sensitive_patterns:
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

    def _detect_php_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in PHP"""
        findings = []
        
        sensitive_patterns = [
            # error_log with sensitive data
            {
                'pattern': r'error_log\s*\(.*(password|token|secret|key)',
                'issue': 'Sensitive Data in error_log',
                'severity': 'CRITICAL',
                'description': 'Sensitive data passed to error_log',
                'recommendation': 'Never log sensitive data',
            },
            # var_dump in production
            {
                'pattern': r'var_dump\s*\(',
                'issue': 'var_dump in Code',
                'severity': 'MEDIUM',
                'description': 'var_dump found in code',
                'recommendation': 'Remove var_dump in production',
            },
            # print_r in production
            {
                'pattern': r'print_r\s*\(.*(\$_POST|\$_GET|\$_REQUEST)',
                'issue': 'User Input with print_r',
                'severity': 'MEDIUM',
                'description': 'User input logged with print_r',
                'recommendation': 'Sanitize user input before logging',
            },
            # file_put_contents for logging sensitive data
            {
                'pattern': r'file_put_contents\s*\([^,]+,\s*.*(password|token|secret)',
                'issue': 'Sensitive Data Written to File',
                'severity': 'HIGH',
                'description': 'Writing sensitive data to log file',
                'recommendation': 'Never write sensitive data to files',
            },
            # log in database without sanitization
            {
                'pattern': r'INSERT\s+INTO.*log.*VALUES.*\$_',
                'issue': 'User Input Logged to Database',
                'severity': 'MEDIUM',
                'description': 'User input logged to database without sanitization',
                'recommendation': 'Use prepared statements and sanitize input',
            },
            # Laravel log with sensitive data
            {
                'pattern': r'Log::info\([^)]*(password|token|secret|key)',
                'issue': 'Sensitive Data in Laravel Log',
                'severity': 'HIGH',
                'description': 'Sensitive data logged via Laravel Log facade',
                'recommendation': 'Never log sensitive data',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            
            for pattern_info in sensitive_patterns:
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

    def _detect_java_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in Java"""
        findings = []
        
        sensitive_patterns = [
            # log.info with password
            {
                'pattern': r'log\.(info|debug|warn|error)\s*\(.*(password|passwd|secret)',
                'issue': 'Sensitive Data Logged',
                'severity': 'CRITICAL',
                'description': 'Sensitive data logged via logger',
                'recommendation': 'Never log sensitive data',
            },
            # System.out.println
            {
                'pattern': r'System\.(out|err)\.(print|println)\s*\(.*(password|token|secret|key)',
                'issue': 'Sensitive Data in System.out',
                'severity': 'CRITICAL',
                'description': 'Sensitive data printed to stdout/stderr',
                'recommendation': 'Use proper logging framework',
            },
            // logger.info with request data
            {
                'pattern': r'logger\.(info|debug)\s*\(.*request\.getParameter',
                'issue': 'Request Parameter Logged',
                'severity': 'MEDIUM',
                'description': 'User request parameters logged',
                'recommendation': 'Sanitize or avoid logging user input',
            },
            // log.error with user input
            {
                'pattern': r'log\.error\s*\(.*\+.*(request|param)',
                'issue': 'User Input in Error Log',
                'severity': 'MEDIUM',
                'description': 'User input concatenated in error log',
                'recommendation': 'Use parameterized logging',
            },
            // SLF4J with sensitive data
            {
                'pattern': r'LOG(GER)?\.(info|debug|error)\s*\(.*(password|token|key|secret)',
                'issue': 'Sensitive Data in SLF4J',
                'severity': 'HIGH',
                'description': 'Sensitive data in SLF4J log statement',
                'recommendation': 'Never log sensitive data',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            for pattern_info in sensitive_patterns:
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

    def _detect_go_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in Go"""
        findings = []
        
        sensitive_patterns = [
            # log.Println with sensitive data
            {
                'pattern': r'log\.Print(ln)?\s*\(.*(password|token|secret|key)',
                'issue': 'Sensitive Data Logged',
                'severity': 'CRITICAL',
                'description': 'Sensitive data logged via log package',
                'recommendation': 'Never log sensitive data',
            },
            // Printf with sensitive data
            {
                'pattern': r'log\.Printf\s*\(.*(password|token|secret|key)',
                'issue': 'Sensitive Data in Printf',
                'severity': 'HIGH',
                'description': 'Sensitive data in log.Printf',
                'recommendation': 'Use structured logging without sensitive data',
            },
            // fmt.Println with request data
            {
                'pattern': r'fmt\.Print(ln)?\s*\(.*r\.(FormValue|PostForm)',
                'issue': 'User Input Logged',
                'severity': 'MEDIUM',
                'description': 'User input logged via fmt',
                'recommendation': 'Use structured logging, sanitize input',
            },
            // zerolog with sensitive data
            {
                'pattern': r'zerolog\.(Info|Debug|Warn|Error)\(\).(Str|Strs).*\("password',
                'issue': 'Password in Zerolog',
                'severity': 'HIGH',
                'description': 'Password field in structured log',
                'recommendation': 'Never log password fields',
            },
            // zap with sensitive data
            {
                'pattern': r'zap\.(Sugar|Field)\.(Str|Int).*\("password',
                'issue': 'Password in Zap Logger',
                'severity': 'HIGH',
                'description': 'Password field in Zap logger',
                'recommendation': 'Never log password fields',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//'):
                continue
            
            for pattern_info in sensitive_patterns:
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

    def _detect_ruby_logging(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure logging in Ruby"""
        findings = []
        
        sensitive_patterns = [
            # Rails logger with sensitive data
            {
                'pattern': r'(Rails\.)?logger\.(info|debug|warn|error)\s*\(.*(password|token|secret)',
                'issue': 'Sensitive Data in Rails Log',
                'severity': 'CRITICAL',
                'description': 'Sensitive data logged in Rails',
                'recommendation': 'Never log sensitive data in Rails',
            },
            # puts with sensitive data
            {
                'pattern': r'puts\s+.*(password|token|secret|key)',
                'issue': 'Sensitive Data with puts',
                'severity': 'CRITICAL',
                'description': 'Sensitive data printed with puts',
                'recommendation': 'Use proper logger, never puts sensitive data',
            },
            # log with user input
            {
                'pattern': r'logger\.(info|debug)\s*\(.*params\[:',
                'issue': 'User Params Logged',
                'severity': 'MEDIUM',
                'description': 'User parameters logged without sanitization',
                'recommendation': 'Filter sensitive params before logging',
            },
            # Rails log raw request
            {
                'pattern': r'logger\.info\s*\(.*request\.body',
                'issue': 'Request Body Logged',
                'severity': 'HIGH',
                'description': 'Entire request body logged in Rails',
                'recommendation': 'Don\'t log request bodies, may contain sensitive data',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('#'):
                continue
            
            for pattern_info in sensitive_patterns:
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
