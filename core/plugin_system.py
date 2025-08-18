#!/usr/bin/env python3
"""
Plugin System for O-Hunter
Extensible plugin architecture for adding custom vulnerability checks
"""

import os
import sys
import importlib
import inspect
import json
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PluginBase(ABC):
    """Base class for all O-Hunter plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = "No description provided"
        self.category = "General"
        self.severity_levels = ["Critical", "High", "Medium", "Low", "Informational"]
    
    @abstractmethod
    def scan(self, target_url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Main scan method that must be implemented by all plugins
        
        Args:
            target_url (str): Target URL to scan
            params (dict): Plugin-specific parameters
            
        Returns:
            list: List of findings in standard format
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category
        }
    
    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        """Validate finding format"""
        required_fields = ['vulnerability', 'severity', 'evidence', 'remediation']
        
        for field in required_fields:
            if field not in finding:
                logger.warning(f"Plugin {self.name}: Missing required field '{field}' in finding")
                return False
        
        if finding['severity'] not in self.severity_levels:
            logger.warning(f"Plugin {self.name}: Invalid severity level '{finding['severity']}'")
            return False
        
        return True
    
    def create_finding(self, vulnerability: str, severity: str, evidence: str, remediation: str, **kwargs) -> Dict[str, Any]:
        """Helper method to create properly formatted findings"""
        finding = {
            'vulnerability': vulnerability,
            'severity': severity,
            'evidence': evidence,
            'remediation': remediation,
            'plugin': self.name,
            'category': self.category
        }
        
        # Add any additional fields
        finding.update(kwargs)
        
        return finding

class PluginManager:
    """Manages loading, registration, and execution of plugins"""
    
    def __init__(self, plugins_dir: str = None):
        """
        Initialize plugin manager
        
        Args:
            plugins_dir (str): Directory containing plugins
        """
        self.plugins_dir = plugins_dir or os.path.join(os.path.dirname(__file__), '..', 'plugins')
        self.plugins = {}
        self.categories = {}
        
        # Create plugins directory if it doesn't exist
        os.makedirs(self.plugins_dir, exist_ok=True)
        
        # Add plugins directory to Python path
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, self.plugins_dir)
    
    def discover_plugins(self) -> List[str]:
        """
        Discover available plugins in the plugins directory
        
        Returns:
            list: List of plugin module names
        """
        plugin_files = []
        
        if not os.path.exists(self.plugins_dir):
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return plugin_files
        
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                plugin_files.append(module_name)
        
        return plugin_files
    
    def load_plugin(self, module_name: str) -> Optional[PluginBase]:
        """
        Load a single plugin from module
        
        Args:
            module_name (str): Name of the plugin module
            
        Returns:
            PluginBase: Loaded plugin instance or None if failed
        """
        try:
            # Import the module
            module = importlib.import_module(module_name)
            
            # Find plugin classes in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, PluginBase) and 
                    obj != PluginBase and 
                    obj.__module__ == module_name):
                    
                    # Instantiate the plugin
                    plugin_instance = obj()
                    logger.info(f"Loaded plugin: {plugin_instance.name}")
                    return plugin_instance
            
            logger.warning(f"No valid plugin class found in module: {module_name}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to load plugin {module_name}: {str(e)}")
            return None
    
    def load_all_plugins(self) -> int:
        """
        Load all available plugins
        
        Returns:
            int: Number of successfully loaded plugins
        """
        plugin_modules = self.discover_plugins()
        loaded_count = 0
        
        for module_name in plugin_modules:
            plugin = self.load_plugin(module_name)
            if plugin:
                self.register_plugin(plugin)
                loaded_count += 1
        
        logger.info(f"Loaded {loaded_count} plugins from {len(plugin_modules)} modules")
        return loaded_count
    
    def register_plugin(self, plugin: PluginBase):
        """
        Register a plugin instance
        
        Args:
            plugin (PluginBase): Plugin instance to register
        """
        plugin_name = plugin.name
        
        if plugin_name in self.plugins:
            logger.warning(f"Plugin {plugin_name} already registered, overwriting")
        
        self.plugins[plugin_name] = plugin
        
        # Organize by category
        category = plugin.category
        if category not in self.categories:
            self.categories[category] = []
        
        if plugin_name not in self.categories[category]:
            self.categories[category].append(plugin_name)
        
        logger.info(f"Registered plugin: {plugin_name} (Category: {category})")
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginBase]:
        """
        Get a specific plugin by name
        
        Args:
            plugin_name (str): Name of the plugin
            
        Returns:
            PluginBase: Plugin instance or None if not found
        """
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_category(self, category: str) -> List[PluginBase]:
        """
        Get all plugins in a specific category
        
        Args:
            category (str): Plugin category
            
        Returns:
            list: List of plugin instances
        """
        plugin_names = self.categories.get(category, [])
        return [self.plugins[name] for name in plugin_names if name in self.plugins]
    
    def list_plugins(self) -> Dict[str, Any]:
        """
        List all registered plugins with their information
        
        Returns:
            dict: Plugin information organized by category
        """
        plugin_info = {}
        
        for category, plugin_names in self.categories.items():
            plugin_info[category] = []
            for plugin_name in plugin_names:
                if plugin_name in self.plugins:
                    plugin = self.plugins[plugin_name]
                    plugin_info[category].append(plugin.get_info())
        
        return plugin_info
    
    def run_plugin(self, plugin_name: str, target_url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Run a specific plugin
        
        Args:
            plugin_name (str): Name of the plugin to run
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: Plugin findings
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            logger.error(f"Plugin not found: {plugin_name}")
            return []
        
        try:
            findings = plugin.scan(target_url, params or {})
            
            # Validate findings
            validated_findings = []
            for finding in findings:
                if plugin.validate_finding(finding):
                    validated_findings.append(finding)
                else:
                    logger.warning(f"Invalid finding from plugin {plugin_name}: {finding}")
            
            logger.info(f"Plugin {plugin_name} found {len(validated_findings)} valid findings")
            return validated_findings
            
        except Exception as e:
            logger.error(f"Error running plugin {plugin_name}: {str(e)}")
            return [{
                'vulnerability': f'Plugin Error - {plugin_name}',
                'severity': 'Low',
                'evidence': f'Error executing plugin: {str(e)}',
                'remediation': 'Check plugin configuration and implementation',
                'plugin': plugin_name,
                'category': 'System'
            }]
    
    def run_category_plugins(self, category: str, target_url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Run all plugins in a specific category
        
        Args:
            category (str): Plugin category
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: Combined findings from all plugins in category
        """
        plugins = self.get_plugins_by_category(category)
        all_findings = []
        
        for plugin in plugins:
            findings = self.run_plugin(plugin.name, target_url, params)
            all_findings.extend(findings)
        
        return all_findings
    
    def run_all_plugins(self, target_url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Run all registered plugins
        
        Args:
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: Combined findings from all plugins
        """
        all_findings = []
        
        for plugin_name in self.plugins:
            findings = self.run_plugin(plugin_name, target_url, params)
            all_findings.extend(findings)
        
        return all_findings
    
    def create_plugin_template(self, plugin_name: str, category: str = "Custom") -> str:
        """
        Create a plugin template file
        
        Args:
            plugin_name (str): Name of the new plugin
            category (str): Plugin category
            
        Returns:
            str: Path to created template file
        """
        template_content = f'''#!/usr/bin/env python3
"""
{plugin_name} Plugin for O-Hunter
Custom vulnerability scanner plugin
"""

import requests
from core.plugin_system import PluginBase

class {plugin_name}Plugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.author = "Your Name"
        self.description = "Description of what this plugin does"
        self.category = "{category}"
    
    def scan(self, target_url, params=None):
        """
        Main scan method
        
        Args:
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: List of findings
        """
        findings = []
        
        try:
            # Your scanning logic here
            response = requests.get(target_url, timeout=10)
            
            # Example finding
            if response.status_code == 200:
                finding = self.create_finding(
                    vulnerability="Example Vulnerability",
                    severity="Informational",
                    evidence=f"Target {{target_url}} is accessible",
                    remediation="This is an example finding from the template"
                )
                findings.append(finding)
        
        except Exception as e:
            finding = self.create_finding(
                vulnerability="Plugin Execution Error",
                severity="Low",
                evidence=f"Error during scan: {{str(e)}}",
                remediation="Check target accessibility and plugin configuration"
            )
            findings.append(finding)
        
        return findings

# Plugin instance (required)
plugin = {plugin_name}Plugin()
'''
        
        template_path = os.path.join(self.plugins_dir, f"{plugin_name.lower()}_plugin.py")
        
        with open(template_path, 'w') as f:
            f.write(template_content)
        
        logger.info(f"Created plugin template: {template_path}")
        return template_path

# Example usage and built-in plugins
class ExamplePlugin(PluginBase):
    """Example plugin demonstrating the plugin system"""
    
    def __init__(self):
        super().__init__()
        self.name = "ExamplePlugin"
        self.version = "1.0.0"
        self.author = "O-Hunter Team"
        self.description = "Example plugin for demonstration"
        self.category = "Example"
    
    def scan(self, target_url, params=None):
        findings = []
        
        finding = self.create_finding(
            vulnerability="Example Check",
            severity="Informational",
            evidence=f"This is an example finding for {target_url}",
            remediation="This is just an example plugin for demonstration purposes"
        )
        findings.append(finding)
        
        return findings

if __name__ == "__main__":
    # Example usage
    manager = PluginManager()
    
    # Register example plugin
    example_plugin = ExamplePlugin()
    manager.register_plugin(example_plugin)
    
    # Load plugins from directory
    manager.load_all_plugins()
    
    # List all plugins
    plugins_info = manager.list_plugins()
    print("Available plugins:")
    for category, plugins in plugins_info.items():
        print(f"\n{category}:")
        for plugin in plugins:
            print(f"  - {plugin['name']} v{plugin['version']} by {plugin['author']}")
            print(f"    {plugin['description']}")
    
    # Run example plugin
    findings = manager.run_plugin("ExamplePlugin", "https://example.com")
    print(f"\nExample plugin findings: {len(findings)}")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")

