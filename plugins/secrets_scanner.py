"""
Secrets Scanner Plugin for Tyr
Detects hardcoded secrets, API keys, passwords, tokens, etc.
FREE - No API key required - Based on entropy and pattern matching
"""

import re
import math
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class SecretsScannerPlugin(AnalyzerPlugin):
    """Plugin for detecting secrets and credentials in source code"""

    @property
    def name(self) -> str:
        return "secrets-scanner"

    @property
    def display_name(self) -> str:
        return "Secrets & Credentials Scanner"

    @property
    def description(self) -> str:
        return "Detects hardcoded secrets, API keys, passwords, and tokens in source code"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        # Scan all text files
        return ['.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.rb', 
                '.env', '.yml', '.yaml', '.json', '.xml', '.config', '.ini', '.sql']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'min-entropy': {
                'help': 'Minimum entropy for high-entropy string detection',
                'type': float,
                'default': 4.5,
            },
            'check-entropy': {
                'help': 'Enable high-entropy string detection',
                'type': bool,
                'default': True,
            },
            'ignore-test-files': {
                'help': 'Ignore files in test directories',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for secrets and credentials"""
        findings = []
        
        # Skip test files if configured
        if self.ignore_test_files and self._is_test_file(file_path):
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Pattern-based detection
            findings.extend(self._detect_by_patterns(file_path, lines))
            
            # Entropy-based detection
            if self.check_entropy:
                findings.extend(self._detect_by_entropy(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _is_test_file(self, file_path: Path) -> bool:
        """Check if file is in a test directory"""
        test_indicators = {'test', 'tests', '__tests__', 'spec', 'specs', 'test_'}
        
        # Check path components
        for part in file_path.parts:
            if part.lower() in test_indicators:
                return True
        
        # Check filename
        name_lower = file_path.name.lower()
        if name_lower.startswith('test_') or name_lower.endswith('_test.py'):
            return True
        if name_lower.endswith('.test.js') or name_lower.endswith('.spec.js'):
            return True
        
        return False

    def _detect_by_patterns(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect secrets using pattern matching"""
        findings = []
        
        patterns = [
            # AWS
            {
                'name': 'AWS Access Key',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'CRITICAL',
            },
            {
                'name': 'AWS Secret Key',
                'pattern': r'aws_secret_access_key\s*=\s*["\']([^"\']+)["\']',
                'severity': 'CRITICAL',
            },
            
            # Generic API Keys
            {
                'name': 'API Key',
                'pattern': r'(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                'severity': 'CRITICAL',
            },
            
            # Passwords
            {
                'name': 'Hardcoded Password',
                'pattern': r'(password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{4,})["\']',
                'severity': 'CRITICAL',
            },
            
            # Tokens
            {
                'name': 'Bearer Token',
                'pattern': r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}',
                'severity': 'HIGH',
            },
            {
                'name': 'GitHub Token',
                'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
                'severity': 'CRITICAL',
            },
            
            # Database Connection Strings
            {
                'name': 'Database Connection String',
                'pattern': r'(mysql|postgresql|mongodb)://[^:]+:[^@]+@',
                'severity': 'CRITICAL',
            },
            
            # Private Keys
            {
                'name': 'Private Key',
                'pattern': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
                'severity': 'CRITICAL',
            },
            
            # Slack Tokens
            {
                'name': 'Slack Token',
                'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,72}',
                'severity': 'HIGH',
            },
            
            # Google API Key
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'severity': 'HIGH',
            },
            
            # Stripe Keys
            {
                'name': 'Stripe API Key',
                'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
                'severity': 'CRITICAL',
            },
            
            # JWT Tokens
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                'severity': 'HIGH',
            },
            
            # Generic Secrets
            {
                'name': 'Secret Key',
                'pattern': r'(secret[_-]?key|client[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
                'severity': 'HIGH',
            },
            
            # SSH Keys in code
            {
                'name': 'SSH Private Key',
                'pattern': r'ssh-rsa\s+[A-Za-z0-9+/=]{100,}',
                'severity': 'CRITICAL',
            },
            
            # Twilio
            {
                'name': 'Twilio API Key',
                'pattern': r'SK[a-z0-9]{32}',
                'severity': 'HIGH',
            },
            
            # Facebook Access Token
            {
                'name': 'Facebook Access Token',
                'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'severity': 'HIGH',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            # Skip comments in some languages
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for pattern_info in patterns:
                matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                for match in matches:
                    # Extract the secret value if it's in a capture group
                    secret_value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group()
                    
                    # Redact the secret in the display
                    redacted = secret_value[:4] + '*' * (len(secret_value) - 8) + secret_value[-4:] if len(secret_value) > 8 else '***'
                    
                    findings.append({
                        'file': str(file_path),
                        'line': i,
                        'column': match.start(),
                        'severity': pattern_info['severity'],
                        'category': 'security',
                        'issue': pattern_info['name'],
                        'message': f'Potential {pattern_info["name"]} detected: {redacted}',
                        'recommendation': 'Move secrets to environment variables or a secure secrets manager',
                        'code_snippet': self._redact_line(line, match.start(), match.end()),
                    })
        
        return findings

    def _detect_by_entropy(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect secrets using entropy analysis"""
        findings = []
        
        # Pattern to find quoted strings
        string_pattern = r'["\']([A-Za-z0-9+/=_\-]{20,})["\']'
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            matches = re.finditer(string_pattern, line)
            for match in matches:
                string_value = match.group(1)
                
                # Calculate entropy
                entropy = self._calculate_entropy(string_value)
                
                if entropy >= self.min_entropy:
                    # Additional checks to reduce false positives
                    if self._looks_like_secret(string_value):
                        redacted = string_value[:4] + '*' * (len(string_value) - 8) + string_value[-4:]
                        
                        findings.append({
                            'file': str(file_path),
                            'line': i,
                            'column': match.start(),
                            'severity': 'HIGH',
                            'category': 'security',
                            'issue': 'High-Entropy String',
                            'message': f'High-entropy string detected (entropy: {entropy:.2f}): {redacted}',
                            'recommendation': 'Verify if this is a secret. If so, move to environment variables',
                            'code_snippet': self._redact_line(line, match.start(), match.end()),
                        })
        
        return findings

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(string)
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

    def _looks_like_secret(self, string: str) -> bool:
        """Additional heuristics to determine if string looks like a secret"""
        # Too short
        if len(string) < 20:
            return False
        
        # Contains spaces (unlikely for secrets)
        if ' ' in string:
            return False
        
        # All same character (test data)
        if len(set(string)) == 1:
            return False
        
        # Looks like a URL or path
        if string.startswith(('http://', 'https://', '/', './')):
            return False
        
        # Looks like a filename
        if '.' in string and string.split('.')[-1] in ['js', 'py', 'php', 'json', 'xml']:
            return False
        
        # Has good character diversity (mix of upper, lower, numbers, symbols)
        has_upper = any(c.isupper() for c in string)
        has_lower = any(c.islower() for c in string)
        has_digit = any(c.isdigit() for c in string)
        
        diversity_score = sum([has_upper, has_lower, has_digit])
        
        return diversity_score >= 2

    def _redact_line(self, line: str, start: int, end: int) -> str:
        """Redact sensitive part of a line"""
        before = line[:start]
        after = line[end:]
        redacted = '***REDACTED***'
        return before + redacted + after
