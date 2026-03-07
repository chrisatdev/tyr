"""
Base class for Tyr vulnerability scanner plugins
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class VulnerabilityPlugin(ABC):
    """
    Base class for vulnerability scanner plugins.
    Similar to nmap's NSE (Nmap Scripting Engine) plugin system.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Plugin name (lowercase, no spaces)
        Example: 'nvd', 'osv', 'github-advisory'
        """
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """
        Human-readable plugin name
        Example: 'National Vulnerability Database'
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Short description of what the plugin does
        """
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
    def requires_api_key(self) -> bool:
        """
        Whether this plugin requires an API key to function.
        Override this if your plugin needs authentication.
        """
        return False

    @property
    def api_key_env_var(self) -> str:
        """
        Environment variable name for the API key.
        Example: 'NVD_API_KEY'
        """
        return None

    def __init__(self, **kwargs):
        """
        Initialize plugin with optional configuration.
        Common kwargs:
            - api_key: API key for authentication
            - delay: Delay between requests in seconds
            - timeout: Request timeout in seconds
        """
        self.config = kwargs
        self.api_key = kwargs.get("api_key")
        self.delay = kwargs.get("delay", 1.0)
        self.timeout = kwargs.get("timeout", 10)

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the plugin is available and properly configured.
        Returns True if the plugin can be used, False otherwise.
        
        Example checks:
        - API key is present if required
        - Service is reachable
        - Dependencies are installed
        """
        pass

    @abstractmethod
    def query_vulnerabilities(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Query vulnerabilities for a specific package and version.
        
        Args:
            package_name: Name of the package (e.g., 'express', 'django')
            version: Version string (e.g., '4.18.2', '3.2.0')
            package_type: Optional package type (e.g., 'npm', 'pypi', 'gem')
        
        Returns:
            List of vulnerability dictionaries with the following structure:
            {
                'id': str,              # CVE-ID or vulnerability ID
                'source': str,          # Plugin name
                'description': str,     # Vulnerability description
                'cvss_score': float,    # CVSS score (0.0-10.0)
                'severity': str,        # CRITICAL, HIGH, MEDIUM, LOW
                'references': List[str], # URLs to more information
                'published': str,       # Publication date (ISO format)
                'cwe': List[str],       # CWE identifiers (optional)
                'affected_versions': str, # Affected version range (optional)
            }
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get plugin metadata for display purposes.
        """
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "requires_api_key": self.requires_api_key,
            "api_key_env_var": self.api_key_env_var,
        }

    def __str__(self) -> str:
        return f"{self.display_name} v{self.version}"

    def __repr__(self) -> str:
        return f"<Plugin: {self.name} v{self.version}>"
