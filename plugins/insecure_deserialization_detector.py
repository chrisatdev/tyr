"""
Insecure Deserialization Detector Plugin for Tyr
Detects insecure deserialization vulnerabilities
FREE - No API key required - Pattern-based detection
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class InsecureDeserializationDetectorPlugin(AnalyzerPlugin):
    """Plugin for detecting insecure deserialization vulnerabilities"""

    @property
    def name(self) -> str:
        return "insecure-deserialization"

    @property
    def display_name(self) -> str:
        return "Insecure Deserialization Detector"

    @property
    def description(self) -> str:
        return "Detects insecure deserialization: pickle.loads, yaml.load, unserialize with user input"

    @property
    def author(self) -> str:
        return "Christian Benitez"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.py', '.php', '.java', '.js', '.ts', '.rb', '.cs']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'strict-mode': {
                'help': 'Flag all deserialization, not just with user input',
                'type': bool,
                'default': False,
            },
            'check-yaml': {
                'help': 'Check YAML deserialization',
                'type': bool,
                'default': True,
            },
        }

    def is_available(self) -> bool:
        """Always available, no dependencies"""
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a file for insecure deserialization"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = file_path.suffix
            
            if ext == '.py':
                findings.extend(self._detect_python_deserialization(file_path, lines))
            elif ext == '.php':
                findings.extend(self._detect_php_deserialization(file_path, lines))
            elif ext == '.java':
                findings.extend(self._detect_java_deserialization(file_path, lines))
            elif ext in ['.js', '.ts']:
                findings.extend(self._detect_javascript_deserialization(file_path, lines))
            elif ext == '.rb':
                findings.extend(self._detect_ruby_deserialization(file_path, lines))
            elif ext == '.cs':
                findings.extend(self._detect_csharp_deserialization(file_path, lines))
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _detect_python_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in Python"""
        findings = []
        
        patterns = [
            # pickle.loads with any input
            {
                'pattern': r'pickle\.loads?\s*\(',
                'issue': 'pickle.loads() Usage',
                'severity': 'CRITICAL',
                'description': 'Using pickle.loads() which can execute arbitrary code',
                'recommendation': 'Use JSON for data exchange, or pickle with signed/encrypted data',
            },
            # pickle.load with file
            {
                'pattern': r'pickle\.load\s*\(',
                'issue': 'pickle.load() Usage',
                'severity': 'HIGH',
                'description': 'Using pickle.load() from file',
                'recommendation': 'Validate data source, use safer serialization formats',
            },
            # yaml.load without safe
            {
                'pattern': r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.BaseLoader',
                'issue': 'yaml.load with BaseLoader',
                'severity': 'MEDIUM',
                'description': 'yaml.load with BaseLoader (partial protection)',
                'recommendation': 'Use yaml.safe_load() for full protection',
            },
            # yaml.load without safe_load
            {
                'pattern': r'yaml\.load\s*\([^)]*(?!safe)',
                'issue': 'yaml.load() without safe_load',
                'severity': 'CRITICAL',
                'description': 'yaml.load() without safe_load allows arbitrary code execution',
                'recommendation': 'Use yaml.safe_load() instead of yaml.load()',
            },
            # yaml.unsafe_load
            {
                'pattern': r'yaml\.unsafe_load\s*\(',
                'issue': 'yaml.unsafe_load() Usage',
                'severity': 'CRITICAL',
                'description': 'yaml.unsafe_load() allows arbitrary code execution',
                'recommendation': 'Use yaml.safe_load() instead',
            },
            # marshal.loads
            {
                'pattern': r'marshal\.loads?\s*\(',
                'issue': 'marshal.loads() Usage',
                'severity': 'CRITICAL',
                'description': 'marshal.loads() can execute arbitrary code',
                'recommendation': 'Avoid marshal, use JSON or pickle with caution',
            },
            # eval with user input
            {
                'pattern': r'eval\s*\([^)]*(request\.|req\.|input\(|sys\.argv)',
                'issue': 'eval() with User Input',
                'severity': 'CRITICAL',
                'description': 'eval() executing user-controlled code',
                'recommendation': 'Never use eval() with user input',
            },
            # exec with user input
            {
                'pattern': r'exec\s*\([^)]*(request\.|req\.|input\(|sys\.argv)',
                'issue': 'exec() with User Input',
                'severity': 'CRITICAL',
                'description': 'exec() executing user-controlled code',
                'recommendation': 'Never use exec() with user input',
            },
            # unpickler with user input
            {
                'pattern': r'pickle\.Unpickler\s*\([^)]*(request\.|req\.)',
                'issue': 'Unpickler with User Input',
                'severity': 'CRITICAL',
                'description': 'Custom Unpickler with user-controlled data',
                'recommendation': 'Use json.loads() instead of pickle',
            },
            # jsonpickle
            {
                'pattern': r'jsonpickle\.(decode|encode)\s*\([^)]*(request\.|req\.)',
                'issue': 'jsonpickle with User Input',
                'severity': 'HIGH',
                'description': 'jsonpickle with user input can execute arbitrary code',
                'recommendation': 'Use json.loads() instead',
            },
            # PyYAML without safe
            {
                'pattern': r'yaml\.(load|unsafe_load|full_load)\s*\([^)]*(?!safe)',
                'issue': 'PyYAML Unsafe Deserialization',
                'severity': 'CRITICAL',
                'description': 'YAML deserialization without safe_load',
                'recommendation': 'Always use yaml.safe_load()',
            },
            # __reduce__ or __setstate__
            {
                'pattern': r'def\s+__reduce__\s*\(',
                'issue': 'Custom __reduce__ Method',
                'severity': 'MEDIUM',
                'description': 'Custom pickle serialization method found',
                'recommendation': 'Ensure no dangerous operations in serialization methods',
            },
            # joblib load
            {
                'pattern': r'joblib\.load\s*\([^)]*(request\.|req\.)',
                'issue': 'joblib.load with User Input',
                'severity': 'HIGH',
                'description': 'joblib.load with user-controlled data',
                'recommendation': 'Validate data source before loading',
            },
            # cloudpickle
            {
                'pattern': r'cloudpickle\.load\s*\(',
                'issue': 'cloudpickle.load Usage',
                'severity': 'HIGH',
                'description': 'cloudpickle can execute arbitrary code',
                'recommendation': 'Avoid with untrusted data',
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

    def _detect_php_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in PHP"""
        findings = []
        
        patterns = [
            # unserialize without options
            {
                'pattern': r'unserialize\s*\([^)]*(?!allowed_classes)',
                'issue': 'unserialize() Usage',
                'severity': 'CRITICAL',
                'description': 'Using unserialize() without allowed_classes option',
                'recommendation': 'Use unserialize($data, ["allowed_classes" => false]) or use JSON',
            },
            # unserialize with user input
            {
                'pattern': r'unserialize\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SESSION)',
                'issue': 'unserialize() with User Input',
                'severity': 'CRITICAL',
                'description': 'unserialize() with user-controlled data',
                'recommendation': 'Never unserialize user input, use JSON instead',
            },
            # var_export with user input
            {
                'pattern': r'var_export\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'var_export with User Input',
                'severity': 'MEDIUM',
                'description': 'var_export with user input can expose sensitive data',
                'recommendation': 'Avoid using var_export with user input',
            },
            # var_dump with user input
            {
                'pattern': r'var_dump\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'var_dump with User Input',
                'severity': 'MEDIUM',
                'description': 'var_dump with user input can expose sensitive data',
                'recommendation': 'Avoid using var_dump with user input in production',
            },
            # print_r with user input
            {
                'pattern': r'print_r\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'print_r with User Input',
                'severity': 'MEDIUM',
                'description': 'print_r with user input can expose sensitive data',
                'recommendation': 'Avoid using print_r with user input in production',
            },
            # preg_replace with /e modifier (deprecated)
            {
                'pattern': r'preg_replace\s*\([^)]*/e',
                'issue': 'preg_replace with /e Modifier',
                'severity': 'CRITICAL',
                'description': 'preg_replace with /e modifier allows code execution',
                'recommendation': 'Use preg_replace_callback instead',
            },
            # assert with user input
            {
                'pattern': r'assert\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'assert() with User Input',
                'severity': 'HIGH',
                'description': 'assert() with user input can execute code',
                'recommendation': 'Never assert user-controlled strings',
            },
            # create_function (deprecated)
            {
                'pattern': r'create_function\s*\(',
                'issue': 'create_function Usage',
                'severity': 'HIGH',
                'description': 'create_function is deprecated and can execute code',
                'recommendation': 'Use anonymous functions instead',
            },
            # call_user_func with user input
            {
                'pattern': r'call_user_func\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)',
                'issue': 'call_user_func with User Input',
                'severity': 'CRITICAL',
                'description': 'call_user_func with user input can call arbitrary functions',
                'recommendation': 'Never call user-controlled function names',
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

    def _detect_java_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in Java"""
        findings = []
        
        patterns = [
            # ObjectInputStream without validation
            {
                'pattern': r'new\s+ObjectInputStream\s*\([^)]*(?!validated|filtered)',
                'issue': 'ObjectInputStream Without Validation',
                'severity': 'CRITICAL',
                'description': 'ObjectInputStream without custom validation',
                'recommendation': 'Use ObjectInputStream with whitelist validation or use JSON',
            },
            # readObject
            {
                'pattern': r'\.readObject\s*\(\s*\)',
                'issue': 'readObject() Usage',
                'severity': 'HIGH',
                'description': 'Deserializing object without validation',
                'recommendation': 'Implement readObject() validation or use safe serialization',
            },
            # XStream without setup
            {
                'pattern': r'new\s+XStream\s*\([^)]*(?!mapper|permission)',
                'issue': 'XStream Without Setup',
                'severity': 'CRITICAL',
                'description': 'XStream without secure configuration',
                'recommendation': 'Setup XStream with denyTypes or use JSON',
            },
            # ObjectMapper from untrusted source
            {
                'pattern': r'new\s+ObjectMapper\s*\(\s*\).*readValue\s*\([^)]*request',
                'issue': 'ObjectMapper with Request Data',
                'severity': 'MEDIUM',
                'description': 'ObjectMapper parsing request data directly',
                'recommendation': 'Validate input before deserialization',
            },
            # Kryo without config
            {
                'pattern': r'new\s+Kryo\s*\(\s*\)',
                'issue': 'Kryo Without Configuration',
                'severity': 'HIGH',
                'description': 'Kryo without registration or safe config',
                'recommendation': 'Register safe classes, configure serialization',
            },
            # readResolve
            {
                'pattern': r'private\s+Object\s+readResolve\s*\(',
                'issue': 'Custom readResolve Method',
                'severity': 'MEDIUM',
                'description': 'Custom readResolve method found',
                'recommendation': 'Ensure readResolve is secure',
            },
            # Java deserialization gadget chain
            {
                'pattern': r'(CommonsCollections|URLClassLoader|ProcessBuilder).*exec',
                'issue': 'Potential Deserialization Gadget',
                'severity': 'HIGH',
                'description': 'Potential gadget chain pattern found',
                'recommendation': 'Ensure no vulnerable libraries in classpath',
            },
            # XMLDecoder usage
            {
                'pattern': r'new\s+XMLDecoder\s*\(',
                'issue': 'XMLDecoder Usage',
                'severity': 'HIGH',
                'description': 'XMLDecoder can execute arbitrary code',
                'recommendation': 'Use JAXB or Jackson for XML parsing',
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

    def _detect_javascript_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in JavaScript"""
        findings = []
        
        patterns = [
            # eval with user input
            {
                'pattern': r'eval\s*\([^)]*(req\.|query|body|params)',
                'issue': 'eval() with User Input',
                'severity': 'CRITICAL',
                'description': 'eval() executing user-controlled code',
                'recommendation': 'Never use eval() with user input',
            },
            # Function constructor with user input
            {
                'pattern': r'new\s+Function\s*\([^)]*(req\.|query|body|params)',
                'issue': 'new Function() with User Input',
                'severity': 'CRITICAL',
                'description': 'Function constructor with user input',
                'recommendation': 'Avoid Function constructor with user input',
            },
            # setTimeout with string
            {
                'pattern': r'setTimeout\s*\(\s*["\']',
                'issue': 'setTimeout with String',
                'severity': 'MEDIUM',
                'description': 'setTimeout with string (similar to eval)',
                'recommendation': 'Use setTimeout with function reference',
            },
            # setInterval with string
            {
                'pattern': r'setInterval\s*\(\s*["\']',
                'issue': 'setInterval with String',
                'severity': 'MEDIUM',
                'description': 'setInterval with string (similar to eval)',
                'recommendation': 'Use setInterval with function reference',
            },
            # vm.runScript
            {
                'pattern': r'vm\.(runScript|runInThisContext)\s*\([^)]*(req\.|query|body)',
                'issue': 'vm.runScript with User Input',
                'severity': 'CRITICAL',
                'description': 'vm.runScript executing user-controlled code',
                'recommendation': 'Avoid vm module with user input',
            },
            # vm.runInNewContext
            {
                'pattern': r'vm\.runIn([^)]*(reqNewContext\s*\\.|query|body)',
                'issue': 'vm.runInNewContext with User Input',
                'severity': 'CRITICAL',
                'description': 'vm.runInNewContext with user input',
                'recommendation': 'Avoid vm with untrusted input',
            },
            # child_process with eval-like patterns
            {
                'pattern': r'child_process\.(exec|execSync)\s*\([^)]*\+[^)]*(req\.|query|body)',
                'issue': 'Command Execution with User Input',
                'severity': 'CRITICAL',
                'description': 'Command execution with string concatenation',
                'recommendation': 'Use execFile/spawn with array arguments',
            },
            # Deserialize with unsafe library
            {
                'pattern': r'require\s*\(\s*["\']node-serialize["\']',
                'issue': 'node-serialize Library',
                'severity': 'CRITICAL',
                'description': 'node-serialize is known to be vulnerable',
                'recommendation': 'Use jsonwebtoken or similar secure library',
            },
            # unsafe-eval in CSP
            {
                'pattern': r'["\']unsafe-eval["\']',
                'issue': 'unsafe-eval in Content-Security-Policy',
                'severity': 'HIGH',
                'description': 'CSP allows eval() and similar',
                'recommendation': 'Remove unsafe-eval from CSP',
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

    def _detect_ruby_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in Ruby"""
        findings = []
        
        patterns = [
            # Marshal.load with user input
            {
                'pattern': r'Marshal\.load\s*\([^)]*(params|request)',
                'issue': 'Marshal.load with User Input',
                'severity': 'CRITICAL',
                'description': 'Marshal.load with user-controlled data',
                'recommendation': 'Never Marshal.load user input, use JSON',
            },
            # YAML.load with user input
            {
                'pattern': r'YAML\.load\s*\([^)]*(params|request)',
                'issue': 'YAML.load with User Input',
                'severity': 'CRITICAL',
                'description': 'YAML.load with user input',
                'recommendation': 'Use YAML.safe_load for untrusted input',
            },
            # eval with user input
            {
                'pattern': r'eval\s*\([^)]*(params|request)',
                'issue': 'eval with User Input',
                'severity': 'CRITICAL',
                'description': 'eval() with user-controlled code',
                'recommendation': 'Never eval() user input',
            },
            # send with user input
            {
                'pattern': r'send\s*\(\s*(params|request)\.',
                'issue': 'send() with User Input',
                'severity': 'HIGH',
                'description': 'Dynamic method call with user input',
                'recommendation': 'Whitelist allowed methods',
            },
            # public_send with user input
            {
                'pattern': r'public_send\s*\([^)]*(params|request)',
                'issue': 'public_send with User Input',
                'severity': 'HIGH',
                'description': 'Dynamic method call with user input',
                'recommendation': 'Whitelist allowed methods',
            },
        ]
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
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

    def _detect_csharp_deserialization(self, file_path: Path, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect insecure deserialization in C#"""
        findings = []
        
        patterns = [
            # BinaryFormatter (deprecated)
            {
                'pattern': r'new\s+BinaryFormatter\s*\(',
                'issue': 'BinaryFormatter Usage',
                'severity': 'CRITICAL',
                'description': 'BinaryFormatter is obsolete and dangerous',
                'recommendation': 'Use System.Text.Json or Newtonsoft.Json',
            },
            # LosFormatter
            {
                'pattern': r'new\s+LosFormatter\s*\(',
                'issue': 'LosFormatter Usage',
                'severity': 'HIGH',
                'description': 'LosFormatter can be exploited',
                'recommendation': 'Use safe serialization methods',
            },
            # ObjectStateFormatter
            {
                'pattern': r'new\s+ObjectStateFormatter\s*\(',
                'issue': 'ObjectStateFormatter Usage',
                'severity': 'HIGH',
                'description': 'ObjectStateFormatter can be exploited',
                'recommendation': 'Use safe serialization methods',
            },
            # SoapFormatter
            {
                'pattern': r'new\s+SoapFormatter\s*\(',
                'issue': 'SoapFormatter Usage',
                'severity': 'HIGH',
                'description': 'SoapFormatter can execute arbitrary code',
                'recommendation': 'Use JSON serialization instead',
            },
            # DataContractSerializer with knownTypes
            {
                'pattern': r'DataContractSerializer\s*\([^)]*knownTypes\s*:\s*',
                'issue': 'DataContractSerializer with KnownTypes',
                'severity': 'MEDIUM',
                'description': 'DataContractSerializer with knownTypes can be exploited',
                'recommendation': 'Limit knownTypes to minimum required',
            },
            # XmlSerializer with unknown types
            {
                'pattern': r'new\s+XmlSerializer\s*\([^)]*Types\s*=\s*',
                'issue': 'XmlSerializer Usage',
                'severity': 'MEDIUM',
                'description': 'XmlSerializer with dynamic types',
                'recommendation': 'Limit serializer to known types only',
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
