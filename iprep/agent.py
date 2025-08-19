"""
Main agent orchestrator for IP and domain reputation checking.

This module coordinates all IP and domain analysis tasks by managing plugins and
aggregating results from multiple sources.
"""

import sys
import importlib
import pkgutil
import inspect
import argparse
import os
from typing import Dict, List, Any, Optional
from .validator import InputValidator
from .aggregator import ResultAggregator
from .plugins.base import BasePlugin, DomainReputationPlugin, DomainContentPlugin, PluginTrafficType
from .debug import debug_logger


class IPRepAgent:
    """Main agent for coordinating IP and domain reputation checks."""
    
    def __init__(self):
        """Initialize the agent with validator, aggregator, and plugin registry."""
        self.validator = InputValidator()
        self.aggregator = ResultAggregator()
        self.plugins: List[BasePlugin] = []
        self.domain_reputation_plugins: List[DomainReputationPlugin] = []
        self.domain_content_plugins: List[DomainContentPlugin] = []
        self._load_plugins()
    
    def _load_plugins(self):
        """Load all available plugins for IP and domain analysis."""
        self._discover_and_load_plugins('iprep.plugins.geolocation')
        self._discover_and_load_plugins('iprep.plugins.reputation')
        self._discover_and_load_domain_plugins('iprep.plugins.domain_reputation')
        self._discover_and_load_domain_plugins('iprep.plugins.domain_content')
    
    def _discover_and_load_plugins(self, package_name: str):
        """
        Discover and load plugins from a package.
        
        Args:
            package_name: The package to search for plugins
        """
        try:
            package = importlib.import_module(package_name)
            for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
                if not ispkg:
                    try:
                        module = importlib.import_module(modname)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and 
                                issubclass(attr, BasePlugin) and 
                                attr != BasePlugin and
                                not attr.__name__.startswith('Base') and
                                not inspect.isabstract(attr)):
                                try:
                                    plugin_instance = attr()
                                    if plugin_instance.is_available():
                                        if self._is_plugin_allowed(plugin_instance):
                                            self.register_plugin(plugin_instance)
                                            print(f"Loaded IP plugin: {plugin_instance.name} ({plugin_instance.traffic_type.value})")
                                        else:
                                            print(f"Skipped IP plugin: {plugin_instance.name} (active plugins disabled)")
                                except Exception as e:
                                    print(f"Failed to instantiate plugin {attr.__name__}: {e}")
                    except Exception as e:
                        print(f"Failed to load module {modname}: {e}")
        except ImportError as e:
            print(f"Could not import package {package_name}: {e}")
    
    def _discover_and_load_domain_plugins(self, package_name: str):
        """
        Discover and load domain-specific plugins from a package.
        
        Args:
            package_name: The package to search for domain plugins
        """
        try:
            package = importlib.import_module(package_name)
            for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
                if not ispkg:
                    try:
                        module = importlib.import_module(modname)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and 
                                (issubclass(attr, DomainReputationPlugin) or issubclass(attr, DomainContentPlugin)) and 
                                attr not in [DomainReputationPlugin, DomainContentPlugin] and
                                not attr.__name__.startswith('Base') and
                                not inspect.isabstract(attr)):
                                try:
                                    plugin_instance = attr()
                                    if plugin_instance.is_available():
                                        if self._is_plugin_allowed(plugin_instance):
                                            self.register_domain_plugin(plugin_instance)
                                            print(f"Loaded domain plugin: {plugin_instance.name} ({plugin_instance.traffic_type.value})")
                                        else:
                                            print(f"Skipped domain plugin: {plugin_instance.name} (active plugins disabled)")
                                except Exception as e:
                                    print(f"Failed to instantiate domain plugin {attr.__name__}: {e}")
                    except Exception as e:
                        print(f"Failed to load module {modname}: {e}")
        except ImportError as e:
            print(f"Could not import package {package_name}: {e}")
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of an IP address.
        
        Args:
            ip_address: The IP address to analyze
            
        Returns:
            Dictionary containing aggregated results from all plugins
            
        Raises:
            ValueError: If IP address is invalid
        """
        import time
        start_time = time.time()
        
        debug_logger.log_analysis_start(ip_address, "IP")
        debug_logger.log_config_info()
        
        if not self.validator.is_valid_ip(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")
        
        results = []
        plugins_used = 0
        
        for plugin in self.plugins:
            try:
                result = plugin.check_ip(ip_address)
                if result:
                    results.append(result)
                    plugins_used += 1
            except Exception as e:
                print(f"Plugin {plugin.__class__.__name__} failed: {e}")
        
        total_time = time.time() - start_time
        debug_logger.log_analysis_complete(ip_address, "IP", total_time, plugins_used)
        
        return self.aggregator.aggregate_results(results)
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a domain name.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            Dictionary containing aggregated results from all domain plugins
            
        Raises:
            ValueError: If domain name is invalid
        """
        import time
        start_time = time.time()
        
        debug_logger.log_analysis_start(domain, "domain")
        debug_logger.log_config_info()
        
        if not self.validator.is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain}")
        
        # Normalize the domain
        normalized_domain = self.validator.normalize_domain(domain)
        
        reputation_results = []
        content_results = []
        plugins_used = 0
        
        # Run domain reputation plugins
        for plugin in self.domain_reputation_plugins:
            try:
                result = plugin.get_domain_reputation(normalized_domain)
                if result:
                    result['plugin_type'] = 'reputation'
                    result['plugin_name'] = plugin.name
                    reputation_results.append(result)
                    plugins_used += 1
            except Exception as e:
                print(f"Domain reputation plugin {plugin.__class__.__name__} failed: {e}")
        
        # Run domain content plugins
        for plugin in self.domain_content_plugins:
            try:
                result = plugin.analyze_domain_content(normalized_domain)
                if result:
                    result['plugin_type'] = 'content'
                    result['plugin_name'] = plugin.name
                    content_results.append(result)
                    plugins_used += 1
            except Exception as e:
                print(f"Domain content plugin {plugin.__class__.__name__} failed: {e}")
        
        total_time = time.time() - start_time
        debug_logger.log_analysis_complete(normalized_domain, "domain", total_time, plugins_used)
        
        return {
            'domain': normalized_domain,
            'reputation_analysis': reputation_results,
            'content_analysis': content_results,
            'summary': self._generate_domain_summary(reputation_results, content_results)
        }
    
    def analyze_input(self, input_value: str) -> Dict[str, Any]:
        """
        Analyze input that could be either an IP address or domain name.
        
        Args:
            input_value: The IP address or domain name to analyze
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            ValueError: If input is neither valid IP nor domain
        """
        if not self.validator.is_valid_input(input_value):
            raise ValueError(f"Invalid input: {input_value} (not a valid IP address or domain name)")
        
        input_type = self.validator.get_input_type(input_value)
        
        if input_type == 'ip':
            return {
                'input_type': 'ip',
                'input': input_value,
                'analysis': self.analyze_ip(input_value)
            }
        elif input_type == 'domain':
            return {
                'input_type': 'domain',
                'input': input_value,
                'analysis': self.analyze_domain(input_value)
            }
        else:
            raise ValueError(f"Invalid input: {input_value} (not a valid IP address or domain name)")
    
    def _generate_domain_summary(self, reputation_results: List[Dict[str, Any]], 
                                content_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of domain analysis results.
        
        Args:
            reputation_results: Results from reputation plugins
            content_results: Results from content plugins
            
        Returns:
            Summary dictionary
        """
        # Calculate overall maliciousness score
        malicious_count = sum(1 for result in reputation_results if result.get('is_malicious', False))
        total_reputation_checks = len(reputation_results)
        
        # Extract key information
        threat_types = set()
        categories = set()
        technologies = set()
        
        for result in reputation_results:
            threat_types.update(result.get('threat_types', []))
            categories.update(result.get('categories', []))
        
        for result in content_results:
            technologies.update(result.get('technologies', []))
            categories.update(result.get('content_categories', []))
        
        return {
            'is_potentially_malicious': malicious_count > 0,
            'malicious_detections': malicious_count,
            'total_reputation_checks': total_reputation_checks,
            'threat_types': list(threat_types),
            'categories': list(categories),
            'technologies_detected': list(technologies),
            'reputation_plugins_run': len(reputation_results),
            'content_plugins_run': len(content_results)
        }
    
    def register_plugin(self, plugin: BasePlugin):
        """Register a new plugin for IP analysis."""
        self.plugins.append(plugin)
    
    def register_domain_plugin(self, plugin):
        """Register a new plugin for domain analysis."""
        if isinstance(plugin, DomainReputationPlugin):
            self.domain_reputation_plugins.append(plugin)
        elif isinstance(plugin, DomainContentPlugin):
            self.domain_content_plugins.append(plugin)
    
    def _is_plugin_allowed(self, plugin) -> bool:
        """
        Check if a plugin is allowed based on its traffic type and configuration.
        
        Args:
            plugin: Plugin instance to check
            
        Returns:
            True if plugin is allowed, False otherwise
        """
        # Always allow passive plugins
        if plugin.is_passive():
            return True
        
        # Only allow active plugins if configuration permits
        from .config import config
        return config.allow_active_plugins()
    
    def get_active_plugins(self) -> list:
        """
        Get list of all active plugins (that directly contact targets).
        
        Returns:
            List of active plugin instances
        """
        active_plugins = []
        
        # Check IP plugins
        for plugin in self.plugins:
            if plugin.is_active():
                active_plugins.append(plugin)
        
        # Check domain plugins
        for plugin in self.domain_reputation_plugins + self.domain_content_plugins:
            if plugin.is_active():
                active_plugins.append(plugin)
        
        return active_plugins
    
    def get_passive_plugins(self) -> list:
        """
        Get list of all passive plugins (that only query APIs about targets).
        
        Returns:
            List of passive plugin instances
        """
        passive_plugins = []
        
        # Check IP plugins
        for plugin in self.plugins:
            if plugin.is_passive():
                passive_plugins.append(plugin)
        
        # Check domain plugins
        for plugin in self.domain_reputation_plugins + self.domain_content_plugins:
            if plugin.is_passive():
                passive_plugins.append(plugin)
        
        return passive_plugins
    
    def get_all_plugins_summary(self) -> dict:
        """
        Get summary of ALL available plugins, regardless of current configuration.
        
        This method discovers all available plugins by temporarily overriding
        the plugin filtering during discovery.
        
        Returns:
            Dictionary with all plugin counts and details
        """
        # Store original plugins
        original_plugins = self.plugins.copy()
        original_domain_reputation = self.domain_reputation_plugins.copy()
        original_domain_content = self.domain_content_plugins.copy()
        
        # Clear current plugins
        self.plugins.clear()
        self.domain_reputation_plugins.clear()
        self.domain_content_plugins.clear()
        
        # Temporarily enable all plugins for discovery
        original_env = os.getenv('IPREP_ALLOW_ACTIVE_PLUGINS')
        os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
        
        try:
            # Redirect print output to suppress plugin loading messages
            import io
            import contextlib
            
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                # Reload plugins with all types enabled
                self._load_plugins()
            
            # Get all plugins
            all_active_plugins = self.get_active_plugins()
            all_passive_plugins = self.get_passive_plugins()
            
            from .config import config
            # Note: we check the original config state, not the temporary one
            original_config_state = original_env is None or original_env.lower() not in ('1', 'true', 'yes', 'on')
            
            return {
                'total_plugins': len(self.plugins) + len(self.domain_reputation_plugins) + len(self.domain_content_plugins),
                'passive_plugins': len(all_passive_plugins),
                'active_plugins': len(all_active_plugins),
                'active_plugin_names': [p.name for p in all_active_plugins],
                'passive_plugin_names': [p.name for p in all_passive_plugins],
                'active_plugins_allowed': not original_config_state
            }
        finally:
            # Restore original environment
            if original_env is not None:
                os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = original_env
            else:
                os.environ.pop('IPREP_ALLOW_ACTIVE_PLUGINS', None)
            
            # Restore original plugins
            self.plugins = original_plugins
            self.domain_reputation_plugins = original_domain_reputation
            self.domain_content_plugins = original_domain_content

    def get_plugin_summary(self) -> dict:
        """
        Get summary of loaded plugins by type.
        
        Returns:
            Dictionary with plugin counts and details
        """
        from .config import config
        
        active_plugins = self.get_active_plugins()
        passive_plugins = self.get_passive_plugins()
        
        return {
            'total_plugins': len(self.plugins) + len(self.domain_reputation_plugins) + len(self.domain_content_plugins),
            'passive_plugins': len(passive_plugins),
            'active_plugins': len(active_plugins),
            'active_plugin_names': [p.name for p in active_plugins],
            'passive_plugin_names': [p.name for p in passive_plugins],
            'active_plugins_allowed': config.allow_active_plugins()
        }


def main():
    """Command-line entry point for the IP and domain reputation agent."""
    parser = argparse.ArgumentParser(
        description='IP and domain reputation analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traffic Types:
  passive  - Only query third-party APIs/databases (no direct target contact)
  active   - Directly contact targets (generates network traffic to target)

Environment Variables:
  IPREP_ALLOW_ACTIVE_PLUGINS=true   - Enable active plugins globally
  IPREP_DEBUG=true                  - Enable debug mode with diagnostic output
  IPREP_DEBUG_LEVEL=basic           - Debug verbosity: basic, detailed, verbose
  IPREP_*_API_KEY                   - API keys for various services

Examples:
  python -m iprep.agent 8.8.8.8                    # Analyze IP (default: passive only)
  python -m iprep.agent example.com                 # Analyze domain (default: passive only)
  python -m iprep.agent --allow-active example.com  # Enable active scanning
  python -m iprep.agent --list-plugins              # Show available plugins
"""
    )
    
    parser.add_argument('target', nargs='?', help='IP address or domain name to analyze')
    parser.add_argument('--allow-active', action='store_true',
                       help='Enable active plugins (allows direct target contact)')
    parser.add_argument('--list-plugins', action='store_true',
                       help='List available plugins and their traffic types')
    parser.add_argument('--show-active', action='store_true',
                       help='Show which plugins would contact the target directly')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode with low-level diagnostic output')
    parser.add_argument('--debug-level', choices=['basic', 'detailed', 'verbose'], default='basic',
                       help='Debug verbosity level (default: basic)')
    
    args = parser.parse_args()
    
    # Set plugin mode if requested
    if args.allow_active:
        os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
    
    # Set debug mode if requested
    if args.debug:
        os.environ['IPREP_DEBUG'] = 'true'
        os.environ['IPREP_DEBUG_LEVEL'] = args.debug_level
    
    agent = IPRepAgent()
    
    # Handle plugin listing
    if args.list_plugins:
        summary = agent.get_all_plugins_summary()
        print(f"Plugin Summary:")
        print(f"  Total plugins loaded: {summary['total_plugins']}")
        print(f"  Passive plugins: {summary['passive_plugins']}")
        print(f"  Active plugins: {summary['active_plugins']}")
        print(f"  Active plugins allowed: {summary['active_plugins_allowed']}")
        print()
        
        print("Passive Plugins (query APIs about target):")
        for name in summary['passive_plugin_names']:
            print(f"  - {name}")
        print()
        
        print("Active Plugins (directly contact target):")
        for name in summary['active_plugin_names']:
            print(f"  - {name}")
        
        return
    
    # Handle show-active option
    if args.show_active:
        active_plugins = agent.get_active_plugins()
        if active_plugins:
            print("Active plugins that would contact the target directly:")
            for plugin in active_plugins:
                print(f"  - {plugin.name}: {plugin.get_traffic_description()}")
        else:
            print("No active plugins loaded (passive-only mode or no active plugins available)")
        return
    
    # Require target for analysis
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    input_value = args.target
    
    try:
        results = agent.analyze_input(input_value)
        input_type = results['input_type']
        analysis = results['analysis']
        
        # Show analysis results
        print(f"Analysis results for {input_value} ({input_type}):")
        
        # Show plugin usage summary
        summary = agent.get_plugin_summary()
        active_used = len([p for p in (agent.get_active_plugins() if input_type == 'domain' else []) 
                          if any(r.get('plugin_name') == p.name for r in 
                                (analysis.get('content_analysis', []) if input_type == 'domain' else []))])
        
        if active_used > 0:
            print(f"  ⚠️  Active scanning: {active_used} plugin(s) contacted the target directly")
        print(f"  ℹ️  Passive analysis: Used {summary['passive_plugins']} passive plugin(s)")
        print()
        
        if input_type == 'ip':
            for key, value in analysis.items():
                print(f"  {key}: {value}")
        else:  # domain
            print(f"  Domain: {analysis['domain']}")
            print(f"  Reputation Analysis ({len(analysis['reputation_analysis'])} sources):")
            for result in analysis['reputation_analysis']:
                plugin_name = result.get('plugin_name', 'Unknown')
                is_malicious = result.get('is_malicious', False)
                threat_types = result.get('threat_types', [])
                print(f"    {plugin_name}: {'MALICIOUS' if is_malicious else 'CLEAN'} {threat_types}")
            
            print(f"  Content Analysis ({len(analysis['content_analysis'])} sources):")
            for result in analysis['content_analysis']:
                plugin_name = result.get('plugin_name', 'Unknown')
                title = result.get('title', 'N/A')
                technologies = result.get('technologies', [])
                print(f"    {plugin_name}: '{title}' [{', '.join(technologies)}]")
            
            summary_data = analysis['summary']
            print(f"  Summary:")
            print(f"    Potentially Malicious: {summary_data['is_potentially_malicious']}")
            print(f"    Detections: {summary_data['malicious_detections']}/{summary_data['total_reputation_checks']}")
            print(f"    Technologies: {', '.join(summary_data['technologies_detected'])}")
            
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()