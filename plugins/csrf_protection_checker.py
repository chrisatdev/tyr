"""
CSRF Protection Checker Plugin for Tyr
Detects missing CSRF protection in forms and API endpoints
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class CSRFProtectionCheckerPlugin(AnalyzerPlugin):
    """Plugin for detecting missing CSRF protection"""

    @property
    def name(self) -> str:
        return "csrf-protection"

    @property
    def display_name(self) -> str:
        return "CSRF Protection Checker"

    @property
    def description(self) -> str:
        return "Detects missing CSRF tokens in forms and state-changing API endpoints"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.php', '.html', '.js', '.jsx', '.ts', '.tsx', '.py', '.vue', '.blade.php']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'critical-methods': {
                'help': 'HTTP methods that require CSRF protection (comma-separated)',
                'type': str,
                'default': 'POST,PUT,DELETE,PATCH',
            },
            'check-forms': {
                'help': 'Check HTML forms for CSRF tokens',
                'type': bool,
                'default': True,
            },
            'check-apis': {
                'help': 'Check API endpoints for CSRF protection',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for missing CSRF protection"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Parse critical methods from argument
            critical_methods = [m.strip().upper() for m in self.critical_methods.split(',')]
            
            # Detect based on file type
            if ext in ['.html', '.php', '.blade.php', '.vue']:
                if self.check_forms:
                    findings.extend(self._detect_html_forms_without_csrf(file_path, lines, content, critical_methods))
            
            if ext == '.php':
                if self.check_apis:
                    findings.extend(self._detect_php_endpoints_without_csrf(file_path, lines, critical_methods))
            
            if ext in ['.js', '.jsx', '.ts', '.tsx']:
                if self.check_apis:
                    findings.extend(self._detect_javascript_endpoints_without_csrf(file_path, lines, critical_methods))
            
            if ext == '.py':
                if self.check_apis:
                    findings.extend(self._detect_python_endpoints_without_csrf(file_path, lines, critical_methods))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_html_forms_without_csrf(self, file_path: Path, lines: List[str], content: str, critical_methods: List[str]) -> List[Dict[str, Any]]:
        """Detect HTML forms without CSRF tokens"""
        findings = []
        
        # Find all forms with method="post" (or other critical methods)
        form_pattern = r'<form[^>]*method\s*=\s*["\']?(POST|PUT|DELETE|PATCH)["\']?[^>]*>'
        
        for match in re.finditer(form_pattern, content, re.IGNORECASE):
            form_start = match.start()
            form_tag = match.group(0)
            
            # Find the closing </form> tag
            form_end_match = re.search(r'</form>', content[form_start:], re.IGNORECASE)
            if form_end_match:
                form_end = form_start + form_end_match.end()
                form_content = content[form_start:form_end]
                
                # Check if form has CSRF token
                has_csrf = self._has_csrf_token(form_content)
                
                if not has_csrf:
                    # Find line number
                    line_num = content[:form_start].count('\n') + 1
                    
                    findings.append({
                        'file': str(file_path),
                        'line': line_num,
                        'severity': 'HIGH',
                        'category': 'security',
                        'issue': 'Form without CSRF Protection',
                        'message': f'Form with method={match.group(1)} is missing CSRF token',
                        'recommendation': 'Add CSRF token field to form (e.g., <input type="hidden" name="_token" value="<?= csrf_token() ?>">)',
                        'code_snippet': form_tag[:100],
                    })
        
        return findings

    def _has_csrf_token(self, form_content: str) -> bool:
        """Check if form content has CSRF token"""
        csrf_patterns = [
            # Laravel CSRF
            r'@csrf',
            r'csrf_token\(\)',
            r'<input[^>]*name\s*=\s*["\']_token["\']',
            r'<input[^>]*name\s*=\s*["\']csrf_token["\']',
            
            # Django CSRF
            r'\{%\s*csrf_token\s*%\}',
            
            # Express/Node CSRF
            r'csrfToken',
            r'_csrf',
            
            # Rails CSRF
            r'authenticity_token',
            
            # Generic CSRF patterns
            r'<input[^>]*name\s*=\s*["\'][^"\']*csrf[^"\']*["\']',
        ]
        
        for pattern in csrf_patterns:
            if re.search(pattern, form_content, re.IGNORECASE):
                return True
        
        return False

    def _detect_php_endpoints_without_csrf(self, file_path: Path, lines: List[str], critical_methods: List[str]) -> List[Dict[str, Any]]:
        """Detect PHP endpoints without CSRF protection"""
        findings = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*'):
                continue
            
            # Check for POST/PUT/DELETE/PATCH handling without CSRF check
            for method in critical_methods:
                # Check $_SERVER['REQUEST_METHOD']
                if re.search(rf'\$_SERVER\[["\']REQUEST_METHOD["\']\]\s*===?\s*["\']({method})["\']', line, re.IGNORECASE):
                    # Look ahead for CSRF verification
                    context_start = max(0, i - 5)
                    context_end = min(len(lines), i + 10)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    if not self._has_csrf_check_php(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'HIGH',
                            'category': 'security',
                            'issue': f'{method} Endpoint without CSRF Protection',
                            'message': f'{method} request handling without CSRF token verification',
                            'recommendation': 'Verify CSRF token before processing request (e.g., verify_csrf_token())',
                            'code_snippet': stripped[:100],
                        })
                
                # Check $_POST, $_PUT, etc. usage
                if re.search(rf'\$_(POST|REQUEST)\s*\[', line) and i > 1:
                    # Look for state-changing operations (INSERT, UPDATE, DELETE, file operations)
                    context_start = max(0, i - 5)
                    context_end = min(len(lines), i + 15)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    if self._has_state_change_php(context) and not self._has_csrf_check_php(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'MEDIUM',
                            'category': 'security',
                            'issue': 'State-Changing Operation without CSRF Check',
                            'message': 'POST data processing with database modification but no CSRF verification',
                            'recommendation': 'Add CSRF token verification before modifying data',
                            'code_snippet': stripped[:100],
                        })
        
        return findings

    def _has_csrf_check_php(self, context: str) -> bool:
        """Check if PHP code has CSRF verification"""
        csrf_patterns = [
            r'verify.*csrf',
            r'check.*csrf',
            r'csrf.*token',
            r'csrf.*verify',
            r'\$_SESSION\[["\']csrf',
            r'hash_equals.*token',
            r'@csrf',
        ]
        
        for pattern in csrf_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False

    def _has_state_change_php(self, context: str) -> bool:
        """Check if PHP code has state-changing operations"""
        state_change_patterns = [
            r'\b(INSERT|UPDATE|DELETE)\s+',
            r'->save\(',
            r'->update\(',
            r'->delete\(',
            r'->create\(',
            r'file_put_contents\(',
            r'unlink\(',
            r'rename\(',
        ]
        
        for pattern in state_change_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False

    def _detect_javascript_endpoints_without_csrf(self, file_path: Path, lines: List[str], critical_methods: List[str]) -> List[Dict[str, Any]]:
        """Detect JavaScript/Node.js API endpoints without CSRF protection"""
        findings = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # Check Express/Hono route definitions
            for method in critical_methods:
                method_lower = method.lower()
                
                # Express/Hono: app.post(), router.post(), etc.
                if re.search(rf'\b(app|router|server)\s*\.\s*({method_lower})\s*\(', line):
                    # Look ahead for CSRF verification
                    context_start = max(0, i - 5)
                    context_end = min(len(lines), i + 20)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    if not self._has_csrf_check_javascript(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'HIGH',
                            'category': 'security',
                            'issue': f'{method} Route without CSRF Protection',
                            'message': f'{method} endpoint without CSRF middleware or token verification',
                            'recommendation': 'Add CSRF middleware (e.g., csurf) or verify token in handler',
                            'code_snippet': stripped[:100],
                        })
            
            # Check Next.js API routes
            if re.search(r'export\s+(default\s+)?async\s+function\s+handler', line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 30)
                context = '\n'.join(lines[context_start:context_end])
                
                # Check if it handles POST/PUT/DELETE
                if re.search(r'req\.method\s*===?\s*["\'](' + '|'.join(critical_methods) + ')["\']', context):
                    if not self._has_csrf_check_javascript(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'HIGH',
                            'category': 'security',
                            'issue': 'Next.js API Route without CSRF Protection',
                            'message': 'State-changing API route without CSRF token verification',
                            'recommendation': 'Verify CSRF token in API handler or use next-csrf',
                            'code_snippet': stripped[:100],
                        })
        
        return findings

    def _has_csrf_check_javascript(self, context: str) -> bool:
        """Check if JavaScript code has CSRF verification"""
        csrf_patterns = [
            r'csrf',
            r'csurf',
            r'next-csrf',
            r'verifyToken',
            r'checkToken',
            r'_csrf',
            r'csrfToken',
            r'x-csrf-token',
        ]
        
        for pattern in csrf_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False

    def _detect_python_endpoints_without_csrf(self, file_path: Path, lines: List[str], critical_methods: List[str]) -> List[Dict[str, Any]]:
        """Detect Python Flask/Django endpoints without CSRF protection"""
        findings = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('#'):
                continue
            
            # Check Flask routes
            for method in critical_methods:
                # Flask: @app.route(..., methods=['POST'])
                if re.search(rf'@.*\.route\([^)]*methods\s*=\s*\[[^\]]*["\']({method})["\']', line):
                    # Look ahead for CSRF verification
                    context_start = max(0, i - 5)
                    context_end = min(len(lines), i + 20)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    if not self._has_csrf_check_python(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'HIGH',
                            'category': 'security',
                            'issue': f'Flask {method} Route without CSRF Protection',
                            'message': f'{method} route without CSRF token verification',
                            'recommendation': 'Use Flask-WTF CSRFProtect or verify token manually',
                            'code_snippet': stripped[:100],
                        })
            
            # Check Django views (function-based)
            if re.search(r'def\s+\w+\s*\([^)]*request[^)]*\):', line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 20)
                context = '\n'.join(lines[context_start:context_end])
                
                # Check if it processes POST data
                if re.search(r'request\.POST', context):
                    if not self._has_csrf_check_python(context):
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': 'MEDIUM',
                            'category': 'security',
                            'issue': 'Django View without CSRF Protection',
                            'message': 'View processes POST data but may be missing @csrf_protect decorator',
                            'recommendation': 'Add @csrf_protect decorator or ensure CSRF middleware is enabled',
                            'code_snippet': stripped[:100],
                        })
        
        return findings

    def _has_csrf_check_python(self, context: str) -> bool:
        """Check if Python code has CSRF verification"""
        csrf_patterns = [
            r'@csrf_protect',
            r'@csrf_exempt',  # Explicitly exempted (still counts as "checked")
            r'CSRFProtect',
            r'csrf_token',
            r'verify.*csrf',
            r'check.*csrf',
        ]
        
        for pattern in csrf_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
