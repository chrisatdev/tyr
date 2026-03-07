"""
SQL Injection Detector Plugin for Tyr
Detects SQL injection vulnerabilities in code
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class SQLInjectionDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting SQL injection vulnerabilities"""

    @property
    def name(self) -> str:
        return "sql-injection"

    @property
    def display_name(self) -> str:
        return "SQL Injection Detector"

    @property
    def description(self) -> str:
        return "Detects SQL injection vulnerabilities: concatenation, unsafe queries, missing prepared statements"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'strict-mode': {
                'help': 'Enable strict mode (flag even potential false positives)',
                'type': bool,
                'default': False,
            },
            'check-orm': {
                'help': 'Check ORM usage for unsafe patterns',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for SQL injection vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Detect based on file type
            if ext == '.php':
                findings.extend(self._detect_php_sqli(file_path, lines))
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_sqli(file_path, lines))
            elif ext == '.py':
                findings.extend(self._detect_python_sqli(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_sqli(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_php_sqli(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SQL injection in PHP code"""
        findings = []
        
        # Dangerous patterns in PHP
        patterns = [
            # String concatenation with variables
            {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\..*\$',
                'issue': 'SQL Query String Concatenation',
                'severity': 'CRITICAL',
                'description': 'SQL query using string concatenation with variables',
                'recommendation': 'Use PDO prepared statements or mysqli_prepare()',
            },
            # Direct use of $_GET, $_POST, $_REQUEST
            {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'User Input in SQL Query',
                'severity': 'CRITICAL',
                'description': 'SQL query directly using user input ($_GET, $_POST, $_REQUEST)',
                'recommendation': 'Use PDO prepared statements with bound parameters',
            },
            # mysql_query (deprecated and unsafe)
            {
                'pattern': r'mysql_query\s*\(',
                'issue': 'Deprecated mysql_query()',
                'severity': 'CRITICAL',
                'description': 'Using deprecated and unsafe mysql_query() function',
                'recommendation': 'Use PDO or mysqli with prepared statements',
            },
            # mysqli_query without prepared statements
            {
                'pattern': r'mysqli_query\s*\([^,]+,\s*["\']?(SELECT|INSERT|UPDATE|DELETE).*(\$|\.)',
                'issue': 'mysqli_query with concatenation',
                'severity': 'HIGH',
                'description': 'Using mysqli_query() with string concatenation',
                'recommendation': 'Use mysqli_prepare() with bound parameters',
            },
            # String interpolation in queries
            {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*"\s*\.\s*\$|"\s*\{\$',
                'issue': 'String Interpolation in SQL',
                'severity': 'HIGH',
                'description': 'SQL query using string interpolation',
                'recommendation': 'Use prepared statements with parameter binding',
            },
            # PDO without prepared statements
            {
                'pattern': r'\$\w+->query\s*\(\s*["\']?(SELECT|INSERT|UPDATE|DELETE).*\$',
                'issue': 'PDO query() with variables',
                'severity': 'HIGH',
                'description': 'Using PDO query() instead of prepare() with variables',
                'recommendation': 'Use $pdo->prepare() followed by execute() with parameters',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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

    def _detect_javascript_sqli(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SQL injection in JavaScript/Node.js code"""
        findings = []
        
        patterns = [
            # Template literals with variables
            {
                'pattern': r'`(SELECT|INSERT|UPDATE|DELETE).*\$\{',
                'issue': 'SQL Template Literal Injection',
                'severity': 'CRITICAL',
                'description': 'SQL query using template literals with variables',
                'recommendation': 'Use parameterized queries with placeholders',
            },
            # String concatenation
            {
                'pattern': r'["\']?(SELECT|INSERT|UPDATE|DELETE)["\']?\s*\+\s*\w+',
                'issue': 'SQL String Concatenation',
                'severity': 'CRITICAL',
                'description': 'SQL query using string concatenation',
                'recommendation': 'Use parameterized queries (e.g., mysql2 placeholders)',
            },
            # mysql/mysql2 query without parameterization
            {
                'pattern': r'\.query\s*\(\s*`?(SELECT|INSERT|UPDATE|DELETE).*\$\{',
                'issue': 'Unsafe Database Query',
                'severity': 'CRITICAL',
                'description': 'Database query with interpolated variables',
                'recommendation': 'Use query("SELECT * FROM users WHERE id = ?", [id])',
            },
            # Sequelize raw queries
            {
                'pattern': r'sequelize\.query\s*\(\s*`.*\$\{',
                'issue': 'Sequelize Raw Query Injection',
                'severity': 'HIGH',
                'description': 'Sequelize raw query with template literal interpolation',
                'recommendation': 'Use sequelize.query with replacements: { replacements: [...] }',
            },
            # req.query, req.body, req.params directly in SQL
            {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*(req\.query|req\.body|req\.params)',
                'issue': 'User Input in SQL Query',
                'severity': 'CRITICAL',
                'description': 'SQL query directly using request data',
                'recommendation': 'Use parameterized queries with placeholders',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
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

    def _detect_python_sqli(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SQL injection in Python code"""
        findings = []
        
        patterns = [
            # String formatting in SQL
            {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*%s|\.format\(',
                'issue': 'SQL String Formatting',
                'severity': 'CRITICAL',
                'description': 'SQL query using string formatting (%s or .format())',
                'recommendation': 'Use parameterized queries with execute("SELECT * FROM users WHERE id = %s", (id,))',
            },
            # F-strings in SQL
            {
                'pattern': r'f["\']?(SELECT|INSERT|UPDATE|DELETE).*\{',
                'issue': 'SQL F-String Injection',
                'severity': 'CRITICAL',
                'description': 'SQL query using f-strings with variables',
                'recommendation': 'Use execute() with tuple parameters instead of f-strings',
            },
            # String concatenation
            {
                'pattern': r'["\']?(SELECT|INSERT|UPDATE|DELETE)["\']?\s*\+\s*\w+',
                'issue': 'SQL String Concatenation',
                'severity': 'CRITICAL',
                'description': 'SQL query using string concatenation',
                'recommendation': 'Use parameterized queries with execute()',
            },
            # execute() with formatted strings
            {
                'pattern': r'\.execute\s*\(\s*f["\']',
                'issue': 'execute() with F-String',
                'severity': 'CRITICAL',
                'description': 'Using execute() with f-string interpolation',
                'recommendation': 'Use execute("SQL", (params,)) with tuple parameters',
            },
            # Raw SQL in Django ORM
            {
                'pattern': r'\.raw\s*\(\s*f["\']',
                'issue': 'Django Raw SQL with F-String',
                'severity': 'HIGH',
                'description': 'Django raw() query with f-string interpolation',
                'recommendation': 'Use raw() with parameters: Model.objects.raw("SQL", [params])',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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

    def _detect_java_sqli(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SQL injection in Java code"""
        findings = []
        
        patterns = [
            # Statement instead of PreparedStatement
            {
                'pattern': r'Statement\s+\w+\s*=.*createStatement\(',
                'issue': 'Using Statement instead of PreparedStatement',
                'severity': 'HIGH',
                'description': 'Using Statement which doesn\'t support parameterization',
                'recommendation': 'Use PreparedStatement with setString(), setInt(), etc.',
            },
            # executeQuery/executeUpdate with concatenation
            {
                'pattern': r'\.execute(Query|Update)\s*\(\s*".*"\s*\+',
                'issue': 'SQL String Concatenation',
                'severity': 'CRITICAL',
                'description': 'SQL query using string concatenation',
                'recommendation': 'Use PreparedStatement with placeholders (?)',
            },
            # String.format in SQL
            {
                'pattern': r'String\.format\s*\(.*SELECT|INSERT|UPDATE|DELETE',
                'issue': 'String.format() in SQL Query',
                'severity': 'HIGH',
                'description': 'Using String.format() to build SQL queries',
                'recommendation': 'Use PreparedStatement with setString(), setInt(), etc.',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
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
