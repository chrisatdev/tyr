"""
Base classes for Tyr analyzer plugins
Support for code analysis, security patterns, and more
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional


class AnalyzerPlugin(ABC):
    """
    Base class for code analyzer plugins.
    These plugins analyze source code directly for issues, patterns, smells, etc.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin identifier (lowercase, no spaces)"""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable plugin name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what the plugin analyzes"""
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """Plugin author name"""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass

    @property
    def supported_extensions(self) -> List[str]:
        """
        File extensions this plugin can analyze.
        Example: ['.py', '.js', '.php']
        Return empty list to analyze all files.
        """
        return []

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        """
        Define custom arguments this plugin accepts.
        
        Format:
        {
            'arg_name': {
                'help': 'Description',
                'type': str,  # or int, float, bool
                'default': 'default_value',
                'required': False,
            }
        }
        
        Example:
        {
            'max-complexity': {
                'help': 'Maximum cyclomatic complexity allowed',
                'type': int,
                'default': 10,
            },
            'ignore-tests': {
                'help': 'Ignore test files',
                'type': bool,
                'default': True,
            }
        }
        """
        return {}

    def __init__(self, **kwargs):
        """
        Initialize plugin with configuration.
        Custom arguments defined in plugin_arguments will be available here.
        """
        self.config = kwargs
        self.verbose = kwargs.get("verbose", False)
        
        # Store custom plugin arguments
        for arg_name, arg_config in self.plugin_arguments.items():
            # Convert arg-name to arg_name for attribute access
            attr_name = arg_name.replace("-", "_")
            value = kwargs.get(arg_name, arg_config.get("default"))
            setattr(self, attr_name, value)

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the plugin can run.
        Returns True if dependencies are met, False otherwise.
        """
        pass

    @abstractmethod
    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Analyze a single file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            List of findings with structure:
            {
                'file': str,              # File path
                'line': int,              # Line number
                'column': int,            # Column number (optional)
                'severity': str,          # CRITICAL, HIGH, MEDIUM, LOW, INFO
                'category': str,          # code-smell, security, performance, etc.
                'issue': str,             # Short issue description
                'message': str,           # Detailed message
                'recommendation': str,    # How to fix
                'code_snippet': str,      # Offending code (optional)
            }
        """
        pass

    def analyze_directory(self, directory: Path) -> List[Dict[str, Any]]:
        """
        Analyze all relevant files in a directory.
        Default implementation: analyze each file matching supported_extensions.
        Override if you need custom directory traversal.
        """
        findings = []
        
        if not self.supported_extensions:
            # Analyze all code files
            extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', 
                         '.rb', '.go', '.c', '.cpp', '.h', '.cs', '.sql'}
        else:
            extensions = set(self.supported_extensions)
        
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if file_path.is_file():
                    # Skip files based on patterns
                    if self._should_skip_file(file_path):
                        continue
                    
                    try:
                        file_findings = self.analyze_file(file_path)
                        findings.extend(file_findings)
                    except Exception as e:
                        if self.verbose:
                            print(f"⚠️  Error analyzing {file_path}: {e}")
        
        return findings

    def _should_skip_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be skipped.
        Override to customize skip logic.
        """
        # Skip common directories
        skip_dirs = {'node_modules', '.git', 'vendor', 'dist', 'build', 
                    '.venv', 'venv', '__pycache__', '.next', '.cache'}
        
        # Check if any parent is a skip directory
        for parent in file_path.parents:
            if parent.name in skip_dirs:
                return True
        
        # Skip minified files
        if '.min.' in file_path.name:
            return True
        
        return False

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata including custom arguments"""
        metadata = {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "supported_extensions": self.supported_extensions,
        }
        
        if self.plugin_arguments:
            metadata["arguments"] = self.plugin_arguments
        
        return metadata

    def __str__(self) -> str:
        return f"{self.display_name} v{self.version}"

    def __repr__(self) -> str:
        return f"<AnalyzerPlugin: {self.name} v{self.version}>"
