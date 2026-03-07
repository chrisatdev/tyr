"""
Path Traversal Detector Plugin for Tyr
Detects path traversal vulnerabilities in file operations
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class PathTraversalDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting path traversal vulnerabilities"""

    @property
    def name(self) -> str:
        return "path-traversal"

    @property
    def display_name(self) -> str:
        return "Path Traversal Detector"

    @property
    def description(self) -> str:
        return "Detects path traversal: file operations with user input, ../ patterns"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.php', '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.rb', '.go']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'check-file-operations': {
                'help': 'Check file read/write operations for user input',
                'type': bool,
                'default': True,
            },
            'check-includes': {
                'help': 'Check include/require statements for path traversal',
                'type': bool,
                'default': True,
            },
            'strict-mode': {
                'help': 'Flag all file operations with variables (not just user input)',
                'type': bool,
                'default': False,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for path traversal vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Detect based on file type
            if ext == '.php':
                findings.extend(self._detect_php_path_traversal(file_path, lines))
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_path_traversal(file_path, lines))
            elif ext == '.py':
                findings.extend(self._detect_python_path_traversal(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_path_traversal(file_path, lines))
            elif ext == '.rb':
                findings.extend(self._detect_ruby_path_traversal(file_path, lines))
            elif ext == '.go':
                findings.extend(self._detect_go_path_traversal(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_php_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in PHP code"""
        findings = []
        
        patterns = [
            # include/require with user input
            {
                'pattern': r'(include|require|include_once|require_once)\s*\(?[^;)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER\[["\']PHP_SELF)',
                'issue': 'Include/Require with User Input',
                'severity': 'CRITICAL',
                'description': 'Using include/require with user-controlled input',
                'recommendation': 'Use whitelist of allowed files, validate against base path, or use realpath()',
            },
            # file_get_contents with user input
            {
                'pattern': r'file_get_contents\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'file_get_contents with User Input',
                'severity': 'HIGH',
                'description': 'Reading file with user-controlled path',
                'recommendation': 'Validate path against whitelist, use basename(), check with realpath()',
            },
            # file_put_contents with user input
            {
                'pattern': r'file_put_contents\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'file_put_contents with User Input',
                'severity': 'CRITICAL',
                'description': 'Writing file with user-controlled path',
                'recommendation': 'Strictly validate path, use whitelist, never trust user input for file paths',
            },
            # fopen with user input
            {
                'pattern': r'fopen\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'fopen with User Input',
                'severity': 'HIGH',
                'description': 'Opening file with user-controlled path',
                'recommendation': 'Validate path, use realpath() and check if it starts with expected base directory',
            },
            # readfile with user input
            {
                'pattern': r'readfile\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'readfile with User Input',
                'severity': 'HIGH',
                'description': 'Reading file with user-controlled path',
                'recommendation': 'Validate path against whitelist of allowed files',
            },
            # unlink with user input
            {
                'pattern': r'unlink\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'unlink with User Input',
                'severity': 'CRITICAL',
                'description': 'Deleting file with user-controlled path',
                'recommendation': 'Never allow user input for file deletion without strict validation',
            },
            # copy/rename with user input
            {
                'pattern': r'(copy|rename)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'File Operation with User Input',
                'severity': 'HIGH',
                'description': 'File copy/rename with user-controlled path',
                'recommendation': 'Validate both source and destination paths',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code path for potential directory traversal',
            },
            # String concatenation in file paths
            {
                'pattern': r'(file_get_contents|fopen|readfile|include|require)\s*\([^)]*\.\s*\$',
                'issue': 'File Path String Concatenation',
                'severity': 'MEDIUM',
                'description': 'Building file path with string concatenation',
                'recommendation': 'Use Path::join() or validate concatenated paths with realpath()',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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

    def _detect_javascript_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in JavaScript/Node.js code"""
        findings = []
        
        patterns = [
            # fs.readFile with user input
            {
                'pattern': r'fs\.(readFile|readFileSync)\s*\([^)]*req\.(query|body|params)',
                'issue': 'fs.readFile with User Input',
                'severity': 'HIGH',
                'description': 'Reading file with user-controlled path from request',
                'recommendation': 'Validate path with path.join(__dirname, ...) and check if it starts with base directory',
            },
            # fs.writeFile with user input
            {
                'pattern': r'fs\.(writeFile|writeFileSync)\s*\([^)]*req\.(query|body|params)',
                'issue': 'fs.writeFile with User Input',
                'severity': 'CRITICAL',
                'description': 'Writing file with user-controlled path from request',
                'recommendation': 'Never trust user input for file paths, use strict validation and whitelist',
            },
            # res.sendFile with user input
            {
                'pattern': r'res\.sendFile\s*\([^)]*req\.(query|body|params)',
                'issue': 'res.sendFile with User Input',
                'severity': 'HIGH',
                'description': 'Sending file with user-controlled path',
                'recommendation': 'Use res.sendFile with root option and validate filename against whitelist',
            },
            # fs.unlink with user input
            {
                'pattern': r'fs\.(unlink|unlinkSync|rm|rmSync)\s*\([^)]*req\.(query|body|params)',
                'issue': 'File Deletion with User Input',
                'severity': 'CRITICAL',
                'description': 'Deleting file with user-controlled path',
                'recommendation': 'Never allow user-controlled file deletion without strict validation',
            },
            # require() with user input
            {
                'pattern': r'require\s*\([^)]*req\.(query|body|params)',
                'issue': 'require() with User Input',
                'severity': 'CRITICAL',
                'description': 'Dynamic require with user-controlled path (can execute arbitrary code)',
                'recommendation': 'Never use require() with user input, use whitelist of allowed modules',
            },
            # Template literals with user input in paths
            {
                'pattern': r'(readFile|writeFile|sendFile|unlink)\s*\(\s*`[^`]*\$\{[^}]*req\.',
                'issue': 'File Operation with Template Literal User Input',
                'severity': 'HIGH',
                'description': 'Using template literal with request data in file path',
                'recommendation': 'Validate and sanitize user input before using in file paths',
            },
            # String concatenation in file paths
            {
                'pattern': r'(readFile|writeFile|sendFile|require)\s*\([^)]*\+[^)]*req\.',
                'issue': 'File Path Concatenation with User Input',
                'severity': 'HIGH',
                'description': 'Concatenating user input into file path',
                'recommendation': 'Use path.join() and validate against base directory',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code for potential directory traversal vulnerability',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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

    def _detect_python_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in Python code"""
        findings = []
        
        patterns = [
            # open() with user input (Flask/Django)
            {
                'pattern': r'open\s*\([^)]*request\.(args|form|values|json|data)',
                'issue': 'open() with User Input',
                'severity': 'HIGH',
                'description': 'Opening file with user-controlled path from request',
                'recommendation': 'Validate path with os.path.join(BASE_DIR, ...) and check realpath()',
            },
            # Path() with user input
            {
                'pattern': r'Path\s*\([^)]*request\.(args|form|values|json|data)',
                'issue': 'Path() with User Input',
                'severity': 'HIGH',
                'description': 'Creating Path object with user-controlled input',
                'recommendation': 'Validate path against base directory using resolve()',
            },
            # send_file with user input (Flask)
            {
                'pattern': r'send_file\s*\([^)]*request\.(args|form|values|json|data)',
                'issue': 'send_file with User Input',
                'severity': 'HIGH',
                'description': 'Sending file with user-controlled path',
                'recommendation': 'Validate filename against whitelist, use safe_join()',
            },
            # os.remove/unlink with user input
            {
                'pattern': r'os\.(remove|unlink)\s*\([^)]*request\.(args|form|values|json|data)',
                'issue': 'File Deletion with User Input',
                'severity': 'CRITICAL',
                'description': 'Deleting file with user-controlled path',
                'recommendation': 'Never allow user-controlled file deletion without strict validation',
            },
            # shutil operations with user input
            {
                'pattern': r'shutil\.(copy|move|rmtree)\s*\([^)]*request\.(args|form|values|json|data)',
                'issue': 'File Operation with User Input',
                'severity': 'CRITICAL',
                'description': 'File operation with user-controlled path',
                'recommendation': 'Validate both source and destination paths against base directory',
            },
            # __import__ with user input
            {
                'pattern': r'__import__\s*\([^)]*request\.',
                'issue': '__import__ with User Input',
                'severity': 'CRITICAL',
                'description': 'Dynamic import with user-controlled module name',
                'recommendation': 'Never use __import__ with user input, use whitelist',
            },
            # String formatting in file paths
            {
                'pattern': r'open\s*\(\s*f["\'][^"\']*\{[^}]*request\.',
                'issue': 'File Path with F-String User Input',
                'severity': 'HIGH',
                'description': 'Using f-string with request data in file path',
                'recommendation': 'Validate user input before using in file paths',
            },
            # String concatenation in file paths
            {
                'pattern': r'open\s*\([^)]*\+[^)]*request\.',
                'issue': 'File Path Concatenation with User Input',
                'severity': 'HIGH',
                'description': 'Concatenating user input into file path',
                'recommendation': 'Use os.path.join() and validate against base directory',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code for potential directory traversal vulnerability',
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

    def _detect_java_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in Java code"""
        findings = []
        
        patterns = [
            # File constructor with user input
            {
                'pattern': r'new\s+File\s*\([^)]*request\.(getParameter|getHeader)',
                'issue': 'File() with User Input',
                'severity': 'HIGH',
                'description': 'Creating File object with user-controlled path',
                'recommendation': 'Validate path with getCanonicalPath() and check it starts with base directory',
            },
            # FileInputStream/FileOutputStream with user input
            {
                'pattern': r'new\s+File(Input|Output)Stream\s*\([^)]*request\.(getParameter|getHeader)',
                'issue': 'File Stream with User Input',
                'severity': 'HIGH',
                'description': 'File stream with user-controlled path',
                'recommendation': 'Validate file path against whitelist',
            },
            # Files.readAllBytes with user input
            {
                'pattern': r'Files\.(readAllBytes|readString|write|delete)\s*\([^)]*request\.',
                'issue': 'Files Operation with User Input',
                'severity': 'HIGH',
                'description': 'File operation with user-controlled path',
                'recommendation': 'Validate path using Path.normalize() and toRealPath()',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code for potential directory traversal vulnerability',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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

    def _detect_ruby_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in Ruby code"""
        findings = []
        
        patterns = [
            # File.open with params
            {
                'pattern': r'File\.(open|read|write|delete)\s*\([^)]*params\[',
                'issue': 'File Operation with User Input',
                'severity': 'HIGH',
                'description': 'File operation with user-controlled path from params',
                'recommendation': 'Validate path with File.expand_path and check it starts with base directory',
            },
            # send_file with params (Rails)
            {
                'pattern': r'send_file\s*\([^)]*params\[',
                'issue': 'send_file with User Input',
                'severity': 'HIGH',
                'description': 'Sending file with user-controlled path',
                'recommendation': 'Validate filename against whitelist',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code for potential directory traversal vulnerability',
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

    def _detect_go_path_traversal(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect path traversal in Go code"""
        findings = []
        
        patterns = [
            # os.Open with user input
            {
                'pattern': r'os\.(Open|Create|Remove)\s*\([^)]*r\.(URL\.Query|FormValue|PostFormValue)',
                'issue': 'File Operation with User Input',
                'severity': 'HIGH',
                'description': 'File operation with user-controlled path from request',
                'recommendation': 'Validate path with filepath.Clean() and check it starts with base directory',
            },
            # ioutil.ReadFile with user input
            {
                'pattern': r'(ioutil|os)\.(ReadFile|WriteFile)\s*\([^)]*r\.(URL\.Query|FormValue|PostFormValue)',
                'issue': 'File Read/Write with User Input',
                'severity': 'HIGH',
                'description': 'File operation with user-controlled path',
                'recommendation': 'Use filepath.Join() with base directory and validate with filepath.Clean()',
            },
            # Directory traversal pattern
            {
                'pattern': r'\.\./|\.\.\\\\',
                'issue': 'Directory Traversal Pattern Detected',
                'severity': 'MEDIUM',
                'description': 'Found ../ or ..\\ pattern which may indicate path traversal',
                'recommendation': 'Review this code for potential directory traversal vulnerability',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
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
