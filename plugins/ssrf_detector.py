"""
SSRF Detector Plugin for Tyr
Detects Server-Side Request Forgery vulnerabilities
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class SSRFDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting SSRF vulnerabilities"""

    @property
    def name(self) -> str:
        return "ssrf"

    @property
    def display_name(self) -> str:
        return "SSRF Detector"

    @property
    def description(self) -> str:
        return "Detects Server-Side Request Forgery: unsafe URL/fetch with user input"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.go']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'check-all-urls': {
                'help': 'Flag all URL fetching, not just with user input',
                'type': bool,
                'default': False,
            },
            'check-localhost': {
                'help': 'Detect requests to localhost/internal networks',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for SSRF vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            if ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_ssrf(file_path, lines))
            elif ext == '.py':
                findings.extend(self._detect_python_ssrf(file_path, lines))
            elif ext == '.php':
                findings.extend(self._detect_php_ssrf(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_ssrf(file_path, lines))
            elif ext == '.go':
                findings.extend(self._detect_go_ssrf(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_javascript_ssrf(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SSRF in JavaScript/Node.js code"""
        findings = []
        
        patterns = [
            # fetch/axios with user input
            {
                'pattern': r'(fetch|axios|request|got|node-fetch)\s*\([^)]*(req\.|process\.env)',
                'issue': 'HTTP Request with User Input',
                'severity': 'CRITICAL',
                'description': 'Making HTTP request with user-controlled URL',
                'recommendation': 'Validate URL against whitelist, use URL parser to check hostname',
            },
            # fetch with template literal
            {
                'pattern': r'fetch\s*\(\s*`[^`]*\$\{',
                'issue': 'fetch() with Template Literal',
                'severity': 'CRITICAL',
                'description': 'fetch() with template literal containing variables',
                'recommendation': 'Validate URL before fetch, use URL constructor to parse',
            },
            # http.request with URL from user
            {
                'pattern': r'http\.(request|get|post)\s*\([^)]*(req\.|query|body|params)',
                'issue': 'http.request with User Input',
                'severity': 'CRITICAL',
                'description': 'http.request with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # http.Agent with user input
            {
                'pattern': r'new\s+https?\.Agent\s*\([^)]*req\.',
                'issue': 'HTTP Agent with User Input',
                'severity': 'HIGH',
                'description': 'Creating HTTP agent with user-controlled options',
                'recommendation': 'Validate all user input',
            },
            # node-fetch with user URL
            {
                'pattern': r'node-fetch\s*\([^)]*(req\.|query|body|params)',
                'issue': 'node-fetch with User Input',
                'severity': 'CRITICAL',
                'description': 'Using node-fetch with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # XMLHttpRequest with user input
            {
                'pattern': r'XMLHttpRequest\.(open|send)\s*\([^)]*(req\.|query|body)',
                'issue': 'XMLHttpRequest with User Input',
                'severity': 'CRITICAL',
                'description': 'XMLHttpRequest with user-controlled URL',
                'recommendation': 'Validate URL before making request',
            },
            # String concatenation in URL
            {
                'pattern': r'(fetch|axios|request)\s*\([^)]*\+[^)]*(req\.|query|body)',
                'issue': 'URL Concatenation with User Input',
                'severity': 'CRITICAL',
                'description': 'Building URL with string concatenation from user input',
                'recommendation': 'Use URL constructor and validate against whitelist',
            },
            # Dangerous protocols
            {
                'pattern': r'(fetch|axios|request)\s*\(\s*["\']?(file:|ftp:|gopher:)',
                'issue': 'Dangerous Protocol in Request',
                'severity': 'HIGH',
                'description': 'Using dangerous protocol (file://, ftp://, gopher://)',
                'recommendation': 'Block dangerous protocols in URL validation',
            },
            # dns.lookup with user input
            {
                'pattern': r'dns\.(lookup|resolve)\s*\([^)]*req\.',
                'issue': 'DNS Lookup with User Input',
                'severity': 'HIGH',
                'description': 'DNS lookup with user-controlled hostname',
                'recommendation': 'Validate hostname against whitelist',
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

    def _detect_python_ssrf(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SSRF in Python code"""
        findings = []
        
        patterns = [
            # requests with user input
            {
                'pattern': r'requests\.(get|post|put|delete|patch)\s*\([^)]*request\.(args|form|values|json|data',
                'issue': 'requests with User Input',
                'severity': 'CRITICAL',
                'description': 'Making HTTP request with user-controlled URL from Flask/Django',
                'recommendation': 'Validate URL against whitelist, use urllib.parse to check hostname',
            },
            # urllib.request with user input
            {
                'pattern': r'urllib\.(request\.urlopen|request\.Request)\s*\([^)]*request\.',
                'issue': 'urllib with User Input',
                'severity': 'CRITICAL',
                'description': 'urllib.request with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # urllib3 with user input
            {
                'pattern': r'urllib3\.(PoolManager|ConnectionPool)\s*\([^)]*request\.',
                'issue': 'urllib3 with User Input',
                'severity': 'CRITICAL',
                'description': 'urllib3 with user-controlled URL',
                'recommendation': 'Validate URL before making request',
            },
            # httpx with user input
            {
                'pattern': r'httpx\.(get|post|put|delete|Client)\s*\([^)]*request\.',
                'issue': 'httpx with User Input',
                'severity': 'CRITICAL',
                'description': 'httpx with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # subprocess with user input (potential SSRF)
            {
                'pattern': r'subprocess\.(run|call|Popen)\s*\([^)]*request\.',
                'issue': 'subprocess with User Input',
                'severity': 'HIGH',
                'description': 'subprocess with user-controlled command',
                'recommendation': 'Never pass user input to subprocess',
            },
            # f-string in requests URL
            {
                'pattern': r'requests\.(get|post)\s*\(\s*f["\']',
                'issue': 'requests with F-String URL',
                'severity': 'CRITICAL',
                'description': 'Using f-string with user input in requests URL',
                'recommendation': 'Use URL constructor and validate',
            },
            # String concatenation in URL
            {
                'pattern': r'(requests|urllib)\.(get|post)\s*\([^)]*\+[^)]*(request\.|args|form)',
                'issue': 'URL Concatenation with User Input',
                'severity': 'CRITICAL',
                'description': 'Building URL with string concatenation from user input',
                'recommendation': 'Use URL constructor and validate against whitelist',
            },
            # socket connection with user input
            {
                'pattern': r'socket\.(connect|bind)\s*\([^)]*request\.',
                'issue': 'Socket Connection with User Input',
                'severity': 'HIGH',
                'description': 'Direct socket connection with user-controlled address',
                'recommendation': 'Validate address against whitelist',
            },
            # curl command injection
            {
                'pattern': r'subprocess\.(run|call)\s*\(\s*["\']curl',
                'issue': 'curl Command Execution',
                'severity': 'HIGH',
                'description': 'Executing curl command, potential SSRF',
                'recommendation': 'Use Python HTTP libraries instead of shell commands',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
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

    def _detect_php_ssrf(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SSRF in PHP code"""
        findings = []
        
        patterns = [
            # file_get_contents with URL
            {
                'pattern': r'file_get_contents\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'file_get_contents with User Input',
                'severity': 'CRITICAL',
                'description': 'Using file_get_contents with user-controlled URL',
                'recommendation': 'Validate URL against whitelist, use filter to block dangerous protocols',
            },
            # curl_exec with user input
            {
                'pattern': r'curl_exec\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'curl_exec with User Input',
                'severity': 'CRITICAL',
                'description': 'Executing curl with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # curl_setopt with user input
            {
                'pattern': r'curl_setopt\s*\([^)]*(CURLOPT_URL|CURLOPT_POSTFIELDS)[^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'curl_setopt with User Input',
                'severity': 'CRITICAL',
                'description': 'Setting curl URL from user input',
                'recommendation': 'Validate all user input before using in curl',
            },
            # fopen with URL
            {
                'pattern': r'fopen\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'fopen with User Input',
                'severity': 'HIGH',
                'description': 'Opening file/URL with user-controlled path',
                'recommendation': 'Validate path against whitelist',
            },
            # simplexml_load_file with user input
            {
                'pattern': r'simplexml_load_(file|string)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'XML Loading with User Input',
                'severity': 'HIGH',
                'description': 'Loading XML from user-controlled source (potential XXE)',
                'recommendation': 'Disable external entities when parsing XML',
            },
            # fsockopen with user input
            {
                'pattern': r'fsockopen\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'fsockopen with User Input',
                'severity': 'HIGH',
                'description': 'Opening socket connection with user-controlled host',
                'recommendation': 'Validate host against whitelist',
            },
            # stream_socket_client with user input
            {
                'pattern': r'stream_socket_client\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'stream_socket_client with User Input',
                'severity': 'HIGH',
                'description': 'Creating socket connection with user-controlled address',
                'recommendation': 'Validate address against whitelist',
            },
            # Guzzle with user input
            {
                'pattern': r'(new\s+)?GuzzleHttp[\\\/].*(get|post|request)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'Guzzle HTTP with User Input',
                'severity': 'CRITICAL',
                'description': 'Guzzle HTTP client with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
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

    def _detect_java_ssrf(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SSRF in Java code"""
        findings = []
        
        patterns = [
            # URL with user input
            {
                'pattern': r'new\s+URL\s*\([^)]*request\.(getParameter|getHeader)',
                'issue': 'URL Constructor with User Input',
                'severity': 'CRITICAL',
                'description': 'Creating URL object with user-controlled string',
                'recommendation': 'Validate URL against whitelist before creating URL object',
            },
            # HttpURLConnection with user input
            {
                'pattern': r'(HttpURLConnection|URLConnection)\s*\.openConnection\s*\([^)]*request\.',
                'issue': 'HTTP Connection with User Input',
                'severity': 'CRITICAL',
                'description': 'Opening HTTP connection with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # OkHttpClient with user input
            {
                'pattern': r'okhttp3\.(OkHttpClient|Request)\s*\([^)]*request\.',
                'issue': 'OkHttp with User Input',
                'severity': 'CRITICAL',
                'description': 'OkHttp client with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # RestTemplate with user input
            {
                'pattern': r'(RestTemplate|HttpClient)\.(getForObject|postForObject|exchange)\s*\([^)]*request\.',
                'issue': 'Spring RestTemplate with User Input',
                'severity': 'CRITICAL',
                'description': 'Spring RestTemplate with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # Apache HttpClient with user input
            {
                'pattern': r'org\.apache\.http\.(client|impl\.execchain)\s*\([^)]*request\.',
                'issue': 'Apache HttpClient with User Input',
                'severity': 'CRITICAL',
                'description': 'Apache HttpClient with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('/*'):
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

    def _detect_go_ssrf(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect SSRF in Go code"""
        findings = []
        
        patterns = [
            # http.Get with user input
            {
                'pattern': r'http\.(Get|Post|Put|Delete|Client\.Do)\s*\([^)]*r\.(URL\.Query|FormValue|PostFormValue)',
                'issue': 'http.Get with User Input',
                'severity': 'CRITICAL',
                'description': 'Making HTTP request with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # http.NewRequest with user input
            {
                'pattern': r'http\.NewRequest\s*\([^)]*r\.(URL\.Query|FormValue|PostFormValue)',
                'issue': 'http.NewRequest with User Input',
                'severity': 'CRITICAL',
                'description': 'Creating HTTP request with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # net/http Get with user input
            {
                'pattern': r'net\/http\.(Get|Post|Client\.Do)\s*\([^)]*r\.',
                'issue': 'net/http with User Input',
                'severity': 'CRITICAL',
                'description': 'net/http package with user-controlled URL',
                'recommendation': 'Validate URL against whitelist',
            },
            # Fetch from request
            {
                'pattern': r'fetch\([^)]*r\.',
                'issue': 'Fetch with User Input',
                'severity': 'CRITICAL',
                'description': 'Making fetch request with user input',
                'recommendation': 'Validate URL against whitelist',
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
