"""
Authentication & Authorization Checker Plugin for Tyr
Detects missing authentication and authorization checks
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class AuthCheckerPlugin(AnalyzerPlugin):
    """Plugin for detecting missing authentication and authorization"""

    @property
    def name(self) -> str:
        return "auth-checker"

    @property
    def display_name(self) -> str:
        return "Authentication & Authorization Checker"

    @property
    def description(self) -> str:
        return "Detects missing auth checks, insecure password handling, unprotected routes"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.php', '.py']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'critical-endpoints': {
                'help': 'Comma-separated list of critical endpoint patterns (e.g., delete,admin,remove)',
                'type': str,
                'default': 'delete,remove,admin,destroy,update,create',
            },
            'check-password-hashing': {
                'help': 'Check for proper password hashing',
                'type': bool,
                'default': True,
            },
            'check-jwt': {
                'help': 'Check for JWT validation',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for authentication/authorization issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            # Parse critical endpoints from config
            critical_patterns = [p.strip() for p in self.critical_endpoints.split(',')]
            
            # Detect based on file type
            if ext in ['.js', '.jsx', '.ts', '.tsx']:
                findings.extend(self._detect_javascript_auth(file_path, lines, content, critical_patterns))
            elif ext == '.php':
                findings.extend(self._detect_php_auth(file_path, lines, critical_patterns))
            elif ext == '.py':
                findings.extend(self._detect_python_auth(file_path, lines, critical_patterns))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_javascript_auth(self, file_path: Path, lines: List[str], content: str, critical_patterns: List[str]) -> List[Dict[str, Any]]:
        """Detect auth issues in JavaScript/Node.js/Express/Hono"""
        findings = []
        
        # Check if auth middleware exists
        has_auth_middleware = bool(re.search(
            r'(authenticat|authMiddleware|requireAuth|isAuth|verifyToken|checkAuth)',
            content,
            re.IGNORECASE
        ))
        
        # Dangerous route patterns
        route_patterns = [
            # Express routes without auth middleware
            {
                'pattern': r'app\.(post|put|delete|patch)\s*\(\s*["\'][^"\']*(' + '|'.join(critical_patterns) + r')[^"\']*["\'](?!.*authenticat)(?!.*requireAuth)',
                'issue': 'Unprotected Critical Route',
                'severity': 'CRITICAL',
                'description': 'Critical route without authentication middleware',
                'recommendation': 'Add authentication middleware: app.post("/delete", requireAuth, handler)',
            },
            # Hono routes without auth
            {
                'pattern': r'app\.(post|put|delete|patch)\s*\(\s*["\'][^"\']*(' + '|'.join(critical_patterns) + r')[^"\']*["\'](?!.*auth)',
                'issue': 'Unprotected Hono Route',
                'severity': 'CRITICAL',
                'description': 'Hono route without authentication check',
                'recommendation': 'Add auth middleware to the route',
            },
            # Next.js API routes without auth check
            {
                'pattern': r'export\s+(default\s+)?async\s+function\s+(POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?!.*session)(?!.*auth)',
                'issue': 'Next.js API Route Without Auth',
                'severity': 'HIGH',
                'description': 'Next.js API route handler without authentication',
                'recommendation': 'Check session/auth: const session = await getServerSession()',
            },
        ]
        
        # Password handling patterns
        password_patterns = [
            # Plain text password comparison
            {
                'pattern': r'(password|pwd)\s*===?\s*(password|pwd)|if\s*\(\s*(password|pwd)\s*==',
                'issue': 'Plain Text Password Comparison',
                'severity': 'CRITICAL',
                'description': 'Comparing passwords without hashing',
                'recommendation': 'Use bcrypt.compare(password, hashedPassword)',
            },
            # Storing password without hashing
            {
                'pattern': r'(password|pwd)\s*:\s*(req\.body\.password|password)(?!.*hash)(?!.*bcrypt)(?!.*crypto)',
                'issue': 'Storing Password Without Hashing',
                'severity': 'CRITICAL',
                'description': 'Storing password without hashing',
                'recommendation': 'Hash password: await bcrypt.hash(password, 10)',
            },
        ]
        
        # JWT patterns
        jwt_patterns = [
            # JWT without verification
            {
                'pattern': r'jwt\.decode\s*\((?!.*verify)',
                'issue': 'JWT Decode Without Verification',
                'severity': 'CRITICAL',
                'description': 'Decoding JWT without verifying signature',
                'recommendation': 'Use jwt.verify() instead of jwt.decode()',
            },
            # Weak JWT secret
            {
                'pattern': r'jwt\.(sign|verify)\s*\([^,]+,\s*["\'](\w{1,15}|secret|test|dev)["\']',
                'issue': 'Weak JWT Secret',
                'severity': 'HIGH',
                'description': 'Using weak or hardcoded JWT secret',
                'recommendation': 'Use strong secret from environment: process.env.JWT_SECRET',
            },
        ]
        
        all_patterns = route_patterns
        if self.check_password_hashing:
            all_patterns.extend(password_patterns)
        if self.check_jwt:
            all_patterns.extend(jwt_patterns)
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            for pattern_info in all_patterns:
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

    def _detect_php_auth(self, file_path: Path, lines: List[str], critical_patterns: List[str]) -> List[Dict[str, Any]]:
        """Detect auth issues in PHP code"""
        findings = []
        
        patterns = [
            # Password comparison without hashing
            {
                'pattern': r'(password|pwd)\s*===?\s*\$_(GET|POST|REQUEST)|if\s*\(\s*\$_\w+\[["\']password["\']\]\s*==',
                'issue': 'Plain Text Password Comparison',
                'severity': 'CRITICAL',
                'description': 'Comparing password without using password_verify()',
                'recommendation': 'Use password_verify($password, $hash)',
            },
            # Storing password without hashing
            {
                'pattern': r'(INSERT|UPDATE).*password.*\$_(GET|POST|REQUEST)(?!.*password_hash)',
                'issue': 'Storing Password Without Hashing',
                'severity': 'CRITICAL',
                'description': 'Storing password in database without hashing',
                'recommendation': 'Use password_hash($password, PASSWORD_DEFAULT)',
            },
            # MD5/SHA1 for passwords (insecure)
            {
                'pattern': r'(md5|sha1)\s*\(\s*\$_(GET|POST|REQUEST)\[["\']password["\']\]',
                'issue': 'Using MD5/SHA1 for Passwords',
                'severity': 'CRITICAL',
                'description': 'Using MD5 or SHA1 for password hashing (insecure)',
                'recommendation': 'Use password_hash() with PASSWORD_DEFAULT or PASSWORD_ARGON2ID',
            },
            # Session without regeneration after login
            {
                'pattern': r'\$_SESSION\[["\']user|session_start\(\)(?!.*session_regenerate_id)',
                'issue': 'Session Fixation Risk',
                'severity': 'MEDIUM',
                'description': 'Setting session without regenerating session ID',
                'recommendation': 'Call session_regenerate_id(true) after successful login',
            },
            # Checking $_SESSION without isset()
            {
                'pattern': r'if\s*\(\s*\$_SESSION\[["\'](?!.*isset)',
                'issue': 'Unsafe Session Check',
                'severity': 'LOW',
                'description': 'Checking session variable without isset()',
                'recommendation': 'Use isset($_SESSION["user"]) to avoid notices',
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

    def _detect_python_auth(self, file_path: Path, lines: List[str], critical_patterns: List[str]) -> List[Dict[str, Any]]:
        """Detect auth issues in Python/Flask/Django code"""
        findings = []
        
        patterns = [
            # Flask routes without @login_required
            {
                'pattern': r'@app\.route\([^)]*(' + '|'.join(critical_patterns) + r')[^)]*\)(?!.*@login_required)(?!.*@require)',
                'issue': 'Flask Route Without Auth Decorator',
                'severity': 'CRITICAL',
                'description': 'Critical Flask route without @login_required decorator',
                'recommendation': 'Add @login_required decorator before the route',
            },
            # Django views without login_required
            {
                'pattern': r'def\s+(' + '|'.join(critical_patterns) + r')\w*\s*\([^)]*request[^)]*\):(?!.*@login_required)(?!.*@permission_required)',
                'issue': 'Django View Without Auth',
                'severity': 'HIGH',
                'description': 'Critical Django view without authentication check',
                'recommendation': 'Add @login_required or check request.user.is_authenticated',
            },
            # Password comparison without hashing
            {
                'pattern': r'(password|pwd)\s*==\s*(password|pwd)|if\s+password\s*==',
                'issue': 'Plain Text Password Comparison',
                'severity': 'CRITICAL',
                'description': 'Comparing passwords without hashing',
                'recommendation': 'Use check_password() or bcrypt.checkpw()',
            },
            # Using hashlib for passwords
            {
                'pattern': r'hashlib\.(md5|sha1|sha256)\s*\(.*password',
                'issue': 'Using hashlib for Passwords',
                'severity': 'HIGH',
                'description': 'Using hashlib for password hashing (not recommended)',
                'recommendation': 'Use bcrypt, argon2, or Django\'s make_password()',
            },
            # JWT decode without verification
            {
                'pattern': r'jwt\.decode\s*\([^,]+,\s*options\s*=\s*\{[^}]*"verify_signature"\s*:\s*False',
                'issue': 'JWT Signature Verification Disabled',
                'severity': 'CRITICAL',
                'description': 'Decoding JWT with signature verification disabled',
                'recommendation': 'Enable signature verification in jwt.decode()',
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
