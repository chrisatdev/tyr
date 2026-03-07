"""
Command Injection Detector Plugin for Tyr
Detects command injection vulnerabilities in code
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class CommandInjectionDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting command injection vulnerabilities"""

    @property
    def name(self) -> str:
        return "command-injection"

    @property
    def display_name(self) -> str:
        return "Command Injection Detector"

    @property
    def description(self) -> str:
        return "Detects command injection: exec(), system(), shell_exec() with user input"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.php', '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.rb']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'strict-mode': {
                'help': 'Flag all command execution, even without obvious user input',
                'type': bool,
                'default': False,
            },
            'check-subprocess': {
                'help': 'Check subprocess and child_process modules',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for command injection vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Detect based on file type
            if ext == '.php':
                findings.extend(self._detect_php_command_injection(file_path, lines))
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_command_injection(file_path, lines))
            elif ext == '.py':
                findings.extend(self._detect_python_command_injection(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_command_injection(file_path, lines))
            elif ext == '.rb':
                findings.extend(self._detect_ruby_command_injection(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_php_command_injection(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect command injection in PHP code"""
        findings = []
        
        patterns = [
            # exec() with user input
            {
                'pattern': r'exec\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$argv)',
                'issue': 'exec() with User Input',
                'severity': 'CRITICAL',
                'description': 'Using exec() with user-controlled input',
                'recommendation': 'Avoid exec(). If necessary, use escapeshellarg() and escapeshellcmd()',
            },
            # system() with user input
            {
                'pattern': r'system\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$argv)',
                'issue': 'system() with User Input',
                'severity': 'CRITICAL',
                'description': 'Using system() with user-controlled input',
                'recommendation': 'Avoid system(). Use safe alternatives or validate/escape input',
            },
            # shell_exec() with user input
            {
                'pattern': r'shell_exec\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$argv)',
                'issue': 'shell_exec() with User Input',
                'severity': 'CRITICAL',
                'description': 'Using shell_exec() with user-controlled input',
                'recommendation': 'Avoid shell_exec(). Use safe PHP functions instead',
            },
            # passthru() with user input
            {
                'pattern': r'passthru\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$argv)',
                'issue': 'passthru() with User Input',
                'severity': 'CRITICAL',
                'description': 'Using passthru() with user-controlled input',
                'recommendation': 'Avoid passthru(). Use safe alternatives',
            },
            # Backticks with variables
            {
                'pattern': r'`[^`]*\$',
                'issue': 'Backtick Command with Variable',
                'severity': 'HIGH',
                'description': 'Using backtick operator with variables',
                'recommendation': 'Avoid backticks. Use safe PHP functions',
            },
            # popen() with user input
            {
                'pattern': r'popen\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'popen() with User Input',
                'severity': 'HIGH',
                'description': 'Using popen() with user-controlled input',
                'recommendation': 'Validate and sanitize input, or use safer alternatives',
            },
            # proc_open() with user input
            {
                'pattern': r'proc_open\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
                'issue': 'proc_open() with User Input',
                'severity': 'HIGH',
                'description': 'Using proc_open() with user-controlled input',
                'recommendation': 'Validate and sanitize all user input',
            },
            # String concatenation in commands
            {
                'pattern': r'(exec|system|shell_exec|passthru)\s*\([^)]*\.\s*\$',
                'issue': 'Command String Concatenation',
                'severity': 'HIGH',
                'description': 'Building command with string concatenation',
                'recommendation': 'Use escapeshellarg() and escapeshellcmd() to sanitize',
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

    def _detect_javascript_command_injection(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect command injection in JavaScript/Node.js code"""
        findings = []
        
        patterns = [
            # child_process.exec with user input
            {
                'pattern': r'(exec|execSync)\s*\(\s*[^)]*\$\{|exec\s*\([^)]*\+|exec\s*\([^)]*req\.(query|body|params)',
                'issue': 'child_process.exec with User Input',
                'severity': 'CRITICAL',
                'description': 'Using exec() with user-controlled input or string interpolation',
                'recommendation': 'Use execFile() or spawn() with array arguments instead of exec()',
            },
            # Template literals in exec
            {
                'pattern': r'exec\s*\(\s*`[^`]*\$\{',
                'issue': 'exec() with Template Literal',
                'severity': 'CRITICAL',
                'description': 'Using exec() with template literal interpolation',
                'recommendation': 'Use execFile() with separate arguments array',
            },
            # child_process.spawn with shell: true
            {
                'pattern': r'spawn\s*\([^)]*\{[^}]*shell\s*:\s*true',
                'issue': 'spawn() with shell: true',
                'severity': 'HIGH',
                'description': 'Using spawn() with shell option enabled',
                'recommendation': 'Avoid shell: true. Use array arguments without shell',
            },
            # eval() with user input (can execute commands)
            {
                'pattern': r'eval\s*\([^)]*req\.(query|body|params)',
                'issue': 'eval() with User Input',
                'severity': 'CRITICAL',
                'description': 'Using eval() with user input (can execute arbitrary code)',
                'recommendation': 'Never use eval() with user input',
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

    def _detect_python_command_injection(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect command injection in Python code"""
        findings = []
        
        patterns = [
            # os.system with user input
            {
                'pattern': r'os\.system\s*\([^)]*\+|os\.system\s*\(f["\']',
                'issue': 'os.system with User Input',
                'severity': 'CRITICAL',
                'description': 'Using os.system() with string concatenation or f-strings',
                'recommendation': 'Use subprocess.run() with list arguments instead',
            },
            # subprocess with shell=True
            {
                'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                'issue': 'subprocess with shell=True',
                'severity': 'HIGH',
                'description': 'Using subprocess with shell=True (command injection risk)',
                'recommendation': 'Use shell=False (default) with list arguments',
            },
            # subprocess with f-string
            {
                'pattern': r'subprocess\.(call|run|Popen)\s*\(\s*f["\']',
                'issue': 'subprocess with F-String',
                'severity': 'CRITICAL',
                'description': 'Using subprocess with f-string interpolation',
                'recommendation': 'Use list arguments: subprocess.run(["cmd", arg1, arg2])',
            },
            # os.popen with user input
            {
                'pattern': r'os\.popen\s*\([^)]*\+|os\.popen\s*\(f["\']',
                'issue': 'os.popen with User Input',
                'severity': 'HIGH',
                'description': 'Using os.popen() with string concatenation',
                'recommendation': 'Use subprocess.run() with list arguments',
            },
            # commands module (deprecated)
            {
                'pattern': r'commands\.(getoutput|getstatusoutput)',
                'issue': 'Deprecated commands Module',
                'severity': 'HIGH',
                'description': 'Using deprecated commands module (command injection risk)',
                'recommendation': 'Use subprocess module instead',
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

    def _detect_java_command_injection(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect command injection in Java code"""
        findings = []
        
        patterns = [
            # Runtime.exec() with string concatenation
            {
                'pattern': r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
                'issue': 'Runtime.exec() with Concatenation',
                'severity': 'CRITICAL',
                'description': 'Using Runtime.exec() with string concatenation',
                'recommendation': 'Use ProcessBuilder with separate arguments',
            },
            # ProcessBuilder with single string
            {
                'pattern': r'new\s+ProcessBuilder\s*\(\s*["\']',
                'issue': 'ProcessBuilder with Single String',
                'severity': 'MEDIUM',
                'description': 'ProcessBuilder with single string (consider using array)',
                'recommendation': 'Use ProcessBuilder with String array for better safety',
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

    def _detect_ruby_command_injection(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect command injection in Ruby code"""
        findings = []
        
        patterns = [
            # system() with interpolation
            {
                'pattern': r'system\s*\([^)]*#\{',
                'issue': 'system() with String Interpolation',
                'severity': 'CRITICAL',
                'description': 'Using system() with string interpolation',
                'recommendation': 'Use system() with separate arguments or validate input',
            },
            # Backticks with interpolation
            {
                'pattern': r'`[^`]*#\{',
                'issue': 'Backtick Command with Interpolation',
                'severity': 'CRITICAL',
                'description': 'Using backticks with string interpolation',
                'recommendation': 'Use Open3 or system() with separate arguments',
            },
            # exec() with interpolation
            {
                'pattern': r'exec\s*\([^)]*#\{',
                'issue': 'exec() with String Interpolation',
                'severity': 'CRITICAL',
                'description': 'Using exec() with string interpolation',
                'recommendation': 'Validate and sanitize all user input',
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
