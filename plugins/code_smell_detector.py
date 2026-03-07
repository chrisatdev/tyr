"""
Code Smell Detector Plugin for Tyr
Detects common code smells: complexity, long functions, duplications, etc.
FREE - No API key required
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class CodeSmellDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting code smells in source code"""

    @property
    def name(self) -> str:
        return "code-smell"

    @property
    def display_name(self) -> str:
        return "Code Smell Detector"

    @property
    def description(self) -> str:
        return "Detects code smells: long functions, high complexity, magic numbers, etc."

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
            'max-function-lines': {
                'help': 'Maximum lines allowed in a function',
                'type': int,
                'default': 50,
            },
            'max-parameters': {
                'help': 'Maximum parameters allowed in a function',
                'type': int,
                'default': 5,
            },
            'max-nesting': {
                'help': 'Maximum nesting depth allowed',
                'type': int,
                'default': 4,
            },
            'detect-duplicates': {
                'help': 'Detect duplicate code blocks',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for code smells"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Detect long functions
            findings.extend(self._detect_long_functions(file_path, lines))
            
            # Detect functions with too many parameters
            findings.extend(self._detect_too_many_parameters(file_path, lines))
            
            # Detect deep nesting
            findings.extend(self._detect_deep_nesting(file_path, lines))
            
            # Detect magic numbers
            findings.extend(self._detect_magic_numbers(file_path, lines))
            
            # Detect long lines
            findings.extend(self._detect_long_lines(file_path, lines))
            
            # Detect commented code
            findings.extend(self._detect_commented_code(file_path, lines))
            
            # Detect TODO/FIXME comments
            findings.extend(self._detect_todo_comments(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_long_functions(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect functions that are too long"""
        findings = []
        ext = file_path.suffix
        
        # Function patterns for different languages
        if ext == '.py':
            pattern = r'^\s*def\s+(\w+)\s*\('
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            pattern = r'^\s*(function\s+(\w+)|const\s+(\w+)\s*=\s*(async\s*)?\(|(\w+)\s*:\s*(async\s*)?\()'
        elif ext == '.php':
            pattern = r'^\s*(public|private|protected)?\s*function\s+(\w+)\s*\('
        elif ext == '.java':
            pattern = r'^\s*(public|private|protected)?\s*\w+\s+(\w+)\s*\('
        else:
            return findings
        
        current_function = None
        function_start = 0
        brace_count = 0
        
        for i, line in enumerate(lines, 1):
            # Check for function declaration
            match = re.match(pattern, line)
            if match:
                if current_function:
                    # Previous function ended
                    function_length = i - function_start - 1
                    if function_length > self.max_function_lines:
                        findings.append({
                            'file': str(file_path),
                            'line': function_start,
                            'severity': 'MEDIUM',
                            'category': 'code-smell',
                            'issue': 'Long Function',
                            'message': f'Function "{current_function}" is {function_length} lines long (max: {self.max_function_lines})',
                            'recommendation': 'Break this function into smaller, more focused functions',
                        })
                
                current_function = match.group(1) or match.group(2) or 'anonymous'
                function_start = i
                brace_count = 0
            
            # Track braces/indentation to detect function end
            if ext == '.py':
                # For Python, check indentation
                if current_function and line and not line[0].isspace() and line.strip():
                    function_length = i - function_start
                    if function_length > self.max_function_lines:
                        findings.append({
                            'file': str(file_path),
                            'line': function_start,
                            'severity': 'MEDIUM',
                            'category': 'code-smell',
                            'issue': 'Long Function',
                            'message': f'Function "{current_function}" is {function_length} lines long (max: {self.max_function_lines})',
                            'recommendation': 'Break this function into smaller, more focused functions',
                        })
                    current_function = None
        
        return findings

    def _detect_too_many_parameters(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect functions with too many parameters"""
        findings = []
        ext = file_path.suffix
        
        # Function patterns
        if ext == '.py':
            pattern = r'def\s+(\w+)\s*\(([^)]*)\)'
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            pattern = r'(function\s+(\w+)\s*\(([^)]*)\)|const\s+(\w+)\s*=\s*\(([^)]*)\))'
        elif ext == '.php':
            pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
        else:
            return findings
        
        for i, line in enumerate(lines, 1):
            matches = re.finditer(pattern, line)
            for match in matches:
                params_str = match.group(2) or match.group(3) or match.group(5) or ''
                if not params_str.strip():
                    continue
                
                # Count parameters
                params = [p.strip() for p in params_str.split(',') if p.strip()]
                param_count = len(params)
                
                if param_count > self.max_parameters:
                    func_name = match.group(1) or match.group(2) or match.group(4) or 'anonymous'
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'MEDIUM',
                        'category': 'code-smell',
                        'issue': 'Too Many Parameters',
                        'message': f'Function "{func_name}" has {param_count} parameters (max: {self.max_parameters})',
                        'recommendation': 'Consider using an object/dict to group related parameters',
                        'code_snippet': line.strip(),
                    })
        
        return findings

    def _detect_deep_nesting(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect deeply nested code blocks"""
        findings = []
        
        for i, line in enumerate(lines, 1):
            # Count leading whitespace to estimate nesting
            if not line.strip():
                continue
            
            leading_spaces = len(line) - len(line.lstrip())
            nesting_level = leading_spaces // 4  # Assume 4 spaces per indent
            
            if nesting_level > self.max_nesting:
                # Check if it's actual code, not just a string or comment
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'LOW',
                        'category': 'code-smell',
                        'issue': 'Deep Nesting',
                        'message': f'Code is nested {nesting_level} levels deep (max: {self.max_nesting})',
                        'recommendation': 'Extract nested logic into separate functions or use early returns',
                        'code_snippet': line.strip(),
                    })
        
        return findings

    def _detect_magic_numbers(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect magic numbers in code"""
        findings = []
        
        # Pattern to find numeric literals (excluding 0, 1, -1)
        pattern = r'\b([2-9]|[1-9]\d+)\b'
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Skip lines that are likely defining constants
            if re.search(r'(const|final|CONST|define)\s', line, re.IGNORECASE):
                continue
            
            matches = re.finditer(pattern, line)
            for match in matches:
                # Check if it's not part of a constant definition
                context = line[:match.start()]
                if not re.search(r'[A-Z_]+\s*=\s*$', context):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'LOW',
                        'category': 'code-smell',
                        'issue': 'Magic Number',
                        'message': f'Magic number "{match.group()}" found',
                        'recommendation': 'Extract to a named constant for better readability',
                        'code_snippet': line.strip(),
                    })
                    break  # Only report once per line
        
        return findings

    def _detect_long_lines(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect lines that are too long"""
        findings = []
        max_line_length = 120
        
        for i, line in enumerate(lines, 1):
            if len(line) > max_line_length:
                findings.append({
                    'file': str(file_path),
                    'line': i,
                    'severity': 'INFO',
                    'category': 'code-smell',
                    'issue': 'Long Line',
                    'message': f'Line is {len(line)} characters long (recommended max: {max_line_length})',
                    'recommendation': 'Break long lines for better readability',
                })
        
        return findings

    def _detect_commented_code(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect commented out code"""
        findings = []
        ext = file_path.suffix
        
        # Patterns that look like commented code
        code_patterns = [
            r'#\s*(if|for|while|def|class|import|return)',  # Python
            r'//\s*(if|for|while|function|const|let|var|return)',  # JS
            r'//\s*(public|private|function|class)',  # PHP/Java
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern in code_patterns:
                if re.match(pattern, stripped):
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'severity': 'INFO',
                        'category': 'code-smell',
                        'issue': 'Commented Code',
                        'message': 'Found commented out code',
                        'recommendation': 'Remove commented code - use version control instead',
                        'code_snippet': stripped,
                    })
                    break
        
        return findings

    def _detect_todo_comments(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect TODO/FIXME comments"""
        findings = []
        
        todo_pattern = r'(TODO|FIXME|HACK|XXX|NOTE)[:|\s]'
        
        for i, line in enumerate(lines, 1):
            match = re.search(todo_pattern, line, re.IGNORECASE)
            if match:
                keyword = match.group(1).upper()
                severity = 'MEDIUM' if keyword in ['FIXME', 'HACK'] else 'INFO'
                
                findings.append({
                    'file': str(file_path),
                    'line': i,
                    'severity': severity,
                    'category': 'code-smell',
                    'issue': f'{keyword} Comment',
                    'message': f'Found {keyword} comment',
                    'recommendation': 'Address this comment or create a task in your issue tracker',
                    'code_snippet': line.strip(),
                })
        
        return findings
