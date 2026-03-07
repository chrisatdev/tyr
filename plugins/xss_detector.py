"""
XSS (Cross-Site Scripting) Detector Plugin for Tyr
Detects XSS vulnerabilities in web applications
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class XSSDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting XSS (Cross-Site Scripting) vulnerabilities"""

    @property
    def name(self) -> str:
        return "xss-detector"

    @property
    def display_name(self) -> str:
        return "XSS Vulnerability Detector"

    @property
    def description(self) -> str:
        return "Detects XSS vulnerabilities: innerHTML, dangerouslySetInnerHTML, unescaped output, eval()"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.php', '.html', '.vue', '.py']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'check-react': {
                'help': 'Check React-specific XSS patterns',
                'type': bool,
                'default': True,
            },
            'check-dom': {
                'help': 'Check DOM manipulation XSS patterns',
                'type': bool,
                'default': True,
            },
            'allow-sanitizers': {
                'help': 'Allow usage if DOMPurify or similar sanitizer is detected',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for XSS vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Detect based on file type
            if ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_xss(file_path, lines, content))
            elif ext == '.php':
                findings.extend(self._detect_php_xss(file_path, lines))
            elif ext == '.html':
                findings.extend(self._detect_html_xss(file_path, lines))
            elif ext == '.vue':
                findings.extend(self._detect_vue_xss(file_path, lines))
            elif ext == '.py':
                findings.extend(self._detect_python_xss(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_javascript_xss(self, file_path: Path, lines: List[str], content: str) -> List[Dict[str, Any]]:
        """Detect XSS in JavaScript/React/TypeScript code"""
        findings = []
        
        # Check if DOMPurify is imported (if allow_sanitizers is True)
        has_sanitizer = False
        if self.allow_sanitizers:
            has_sanitizer = bool(re.search(r'(DOMPurify|xss|sanitize-html)', content, re.IGNORECASE))
        
        patterns = [
            # innerHTML with variables
            {
                'pattern': r'\.innerHTML\s*=\s*(?!["\'`])[^;]+',
                'issue': 'Unsafe innerHTML Assignment',
                'severity': 'CRITICAL' if not has_sanitizer else 'HIGH',
                'description': 'Setting innerHTML with unsanitized content',
                'recommendation': 'Use textContent or sanitize with DOMPurify before setting innerHTML',
            },
            # dangerouslySetInnerHTML in React
            {
                'pattern': r'dangerouslySetInnerHTML\s*=\s*\{\{.*__html:',
                'issue': 'dangerouslySetInnerHTML in React',
                'severity': 'CRITICAL' if not has_sanitizer else 'HIGH',
                'description': 'Using dangerouslySetInnerHTML without sanitization',
                'recommendation': 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML',
            },
            # eval() usage
            {
                'pattern': r'\beval\s*\(',
                'issue': 'Dangerous eval() Usage',
                'severity': 'CRITICAL',
                'description': 'Using eval() which can execute arbitrary code',
                'recommendation': 'Avoid eval(). Use JSON.parse() for JSON or safer alternatives',
            },
            # Function() constructor
            {
                'pattern': r'new\s+Function\s*\(',
                'issue': 'Function Constructor Usage',
                'severity': 'HIGH',
                'description': 'Using Function constructor which can execute arbitrary code',
                'recommendation': 'Avoid Function constructor. Use safer alternatives',
            },
            # document.write with variables
            {
                'pattern': r'document\.write\s*\(\s*(?!["\'])',
                'issue': 'Unsafe document.write()',
                'severity': 'HIGH',
                'description': 'Using document.write() with variables',
                'recommendation': 'Use DOM manipulation methods and sanitize input',
            },
            # outerHTML with variables
            {
                'pattern': r'\.outerHTML\s*=\s*(?!["\'`])',
                'issue': 'Unsafe outerHTML Assignment',
                'severity': 'HIGH',
                'description': 'Setting outerHTML with unsanitized content',
                'recommendation': 'Sanitize content before setting outerHTML',
            },
            # insertAdjacentHTML with variables
            {
                'pattern': r'\.insertAdjacentHTML\s*\([^,]+,\s*(?!["\'])',
                'issue': 'Unsafe insertAdjacentHTML',
                'severity': 'HIGH',
                'description': 'Using insertAdjacentHTML with unsanitized content',
                'recommendation': 'Sanitize HTML content with DOMPurify',
            },
            # jQuery html() with variables
            {
                'pattern': r'\$\([^)]+\)\.html\s*\(\s*(?!["\'])',
                'issue': 'Unsafe jQuery .html()',
                'severity': 'HIGH',
                'description': 'Using jQuery .html() with unsanitized content',
                'recommendation': 'Use .text() for plain text or sanitize with DOMPurify',
            },
            # v-html in Vue (check in vue files too)
            {
                'pattern': r'v-html\s*=\s*["\']?(?!sanitize)',
                'issue': 'Vue v-html Directive',
                'severity': 'HIGH',
                'description': 'Using v-html without sanitization',
                'recommendation': 'Sanitize HTML before using v-html directive',
            },
            # location.href with user input
            {
                'pattern': r'location\.href\s*=\s*.*(req\.|params|query|body|input|user)',
                'issue': 'Open Redirect via location.href',
                'severity': 'MEDIUM',
                'description': 'Setting location.href with user-controlled data',
                'recommendation': 'Validate and whitelist URLs before redirecting',
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

    def _detect_php_xss(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect XSS in PHP code"""
        findings = []
        
        patterns = [
            # echo without htmlspecialchars/htmlentities
            {
                'pattern': r'echo\s+\$_(GET|POST|REQUEST|COOKIE)|echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
                'issue': 'Unescaped Echo of User Input',
                'severity': 'CRITICAL',
                'description': 'Echoing user input without escaping',
                'recommendation': 'Use htmlspecialchars($_GET[...], ENT_QUOTES, \'UTF-8\')',
            },
            # print without escaping
            {
                'pattern': r'print\s+\$_(GET|POST|REQUEST|COOKIE)',
                'issue': 'Unescaped Print of User Input',
                'severity': 'CRITICAL',
                'description': 'Printing user input without escaping',
                'recommendation': 'Use htmlspecialchars() to escape output',
            },
            # <?= without escaping
            {
                'pattern': r'<\?=\s*\$_(GET|POST|REQUEST|COOKIE)',
                'issue': 'Unescaped Short Echo Tag',
                'severity': 'CRITICAL',
                'description': 'Using <?= with user input without escaping',
                'recommendation': 'Use <?= htmlspecialchars($var, ENT_QUOTES, \'UTF-8\') ?>',
            },
            # Direct variable output in HTML
            {
                'pattern': r'<[^>]*>\s*\$_(GET|POST|REQUEST|COOKIE)',
                'issue': 'Direct Variable in HTML',
                'severity': 'HIGH',
                'description': 'User input directly embedded in HTML',
                'recommendation': 'Escape all user input with htmlspecialchars()',
            },
            # eval() in PHP
            {
                'pattern': r'\beval\s*\(',
                'issue': 'Dangerous eval() Usage',
                'severity': 'CRITICAL',
                'description': 'Using eval() which can execute arbitrary code',
                'recommendation': 'Avoid eval(). Refactor to use safer alternatives',
            },
            # create_function (deprecated and dangerous)
            {
                'pattern': r'create_function\s*\(',
                'issue': 'Deprecated create_function()',
                'severity': 'HIGH',
                'description': 'Using deprecated and dangerous create_function()',
                'recommendation': 'Use anonymous functions or closures instead',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            
            # Check if line has htmlspecialchars/htmlentities (safe)
            if 'htmlspecialchars' in line or 'htmlentities' in line or 'esc_html' in line:
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

    def _detect_html_xss(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect XSS in HTML templates"""
        findings = []
        
        patterns = [
            # Inline event handlers with variables
            {
                'pattern': r'on\w+\s*=\s*["\'][^"\']*\$\{|on\w+\s*=\s*["\'][^"\']*<%=',
                'issue': 'Variable in Inline Event Handler',
                'severity': 'HIGH',
                'description': 'Using variables in inline event handlers',
                'recommendation': 'Avoid inline event handlers. Use addEventListener instead',
            },
            # javascript: protocol with variables
            {
                'pattern': r'href\s*=\s*["\']javascript:.*\$\{|href\s*=\s*["\']javascript:.*<%=',
                'issue': 'Variable in javascript: URL',
                'severity': 'HIGH',
                'description': 'Using variables in javascript: protocol',
                'recommendation': 'Avoid javascript: protocol. Use proper event handlers',
            },
        ]
        
        for i, line in enumerate(lines, 1):
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
                        'code_snippet': line.strip()[:100],
                    })
        
        return findings

    def _detect_vue_xss(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect XSS in Vue.js templates"""
        findings = []
        
        patterns = [
            # v-html without sanitization
            {
                'pattern': r'v-html\s*=\s*["\'](?!.*sanitize)(?!.*DOMPurify)',
                'issue': 'Unsafe v-html Directive',
                'severity': 'HIGH',
                'description': 'Using v-html without proper sanitization',
                'recommendation': 'Sanitize HTML content before using v-html',
            },
        ]
        
        for i, line in enumerate(lines, 1):
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
                        'code_snippet': line.strip()[:100],
                    })
        
        return findings

    def _detect_python_xss(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect XSS in Python web frameworks"""
        findings = []
        
        patterns = [
            # Flask render_template_string without escaping
            {
                'pattern': r'render_template_string\s*\([^)]*\+|render_template_string\s*\(f["\']',
                'issue': 'Unsafe render_template_string',
                'severity': 'CRITICAL',
                'description': 'Using render_template_string with string concatenation',
                'recommendation': 'Use render_template() with Jinja2 auto-escaping',
            },
            # Django mark_safe
            {
                'pattern': r'mark_safe\s*\(',
                'issue': 'Django mark_safe Usage',
                'severity': 'HIGH',
                'description': 'Using mark_safe() which bypasses auto-escaping',
                'recommendation': 'Ensure content is properly sanitized before using mark_safe()',
            },
            # Django safe filter
            {
                'pattern': r'\|\s*safe\s*[}\]]',
                'issue': 'Django |safe Filter',
                'severity': 'HIGH',
                'description': 'Using |safe filter which bypasses auto-escaping',
                'recommendation': 'Only use |safe with trusted, sanitized content',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('#'):
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
