"""
Debug utilities for iprep.

This module provides debugging functionality for plugin calls, outputs,
and other low-level diagnostics when debug mode is enabled.
"""

import sys
import time
import json
from typing import Any, Dict, Optional, Callable
from functools import wraps
from .config import config


class DebugLogger:
    """Debug logger for low-level diagnostics."""
    
    def __init__(self):
        """Initialize debug logger."""
        self.start_time = time.time()
        self.plugin_call_count = 0
        
    def log(self, level: str, message: str, data: Optional[Dict[str, Any]] = None):
        """
        Log debug message with optional data.
        
        Args:
            level: Debug level ('basic', 'detailed', 'verbose')
            message: Debug message
            data: Optional data to include
        """
        if not config.is_debug_mode():
            return
            
        current_level = config.get_debug_level()
        
        # Check if this message should be shown based on level
        level_hierarchy = {'basic': 0, 'detailed': 1, 'verbose': 2}
        if level_hierarchy.get(level, 0) > level_hierarchy.get(current_level, 0):
            return
            
        timestamp = time.time() - self.start_time
        prefix = f"[DEBUG +{timestamp:.3f}s]"
        
        print(f"{prefix} {message}", file=sys.stderr)
        
        if data and current_level in ('detailed', 'verbose'):
            self._print_data(data, current_level)
    
    def _print_data(self, data: Dict[str, Any], level: str):
        """Print debug data with appropriate formatting."""
        try:
            if level == 'verbose':
                # Full JSON output for verbose mode
                formatted = json.dumps(data, indent=2, default=str)
                for line in formatted.split('\n'):
                    print(f"[DEBUG]   {line}", file=sys.stderr)
            else:
                # Simplified output for detailed mode
                for key, value in data.items():
                    if isinstance(value, dict):
                        print(f"[DEBUG]   {key}: {len(value)} items", file=sys.stderr)
                    elif isinstance(value, list):
                        print(f"[DEBUG]   {key}: [{len(value)} items]", file=sys.stderr)
                    elif isinstance(value, str) and len(value) > 100:
                        print(f"[DEBUG]   {key}: '{value[:97]}...'", file=sys.stderr)
                    else:
                        print(f"[DEBUG]   {key}: {value}", file=sys.stderr)
        except Exception:
            print("[DEBUG]   <data formatting error>", file=sys.stderr)
    
    def log_plugin_call(self, plugin_name: str, method: str, args: tuple = (), kwargs: Dict[str, Any] = None):
        """Log plugin method call."""
        self.plugin_call_count += 1
        kwargs = kwargs or {}
        
        args_str = ", ".join(str(arg) for arg in args[:2])  # Limit args shown
        if len(args) > 2:
            args_str += f", ... (+{len(args)-2} more)"
            
        kwargs_str = ", ".join(f"{k}={v}" for k, v in list(kwargs.items())[:2])
        if len(kwargs) > 2:
            kwargs_str += f", ... (+{len(kwargs)-2} more)"
            
        call_args = ", ".join(filter(None, [args_str, kwargs_str]))
        
        self.log('basic', f"Plugin call #{self.plugin_call_count}: {plugin_name}.{method}({call_args})")
    
    def log_plugin_result(self, plugin_name: str, method: str, result: Any, execution_time: float):
        """Log plugin method result."""
        result_summary = self._summarize_result(result)
        
        self.log('basic', f"Plugin result: {plugin_name}.{method} -> {result_summary} ({execution_time:.3f}s)")
        
        if config.get_debug_level() in ('detailed', 'verbose'):
            self.log('detailed', f"Full result data for {plugin_name}.{method}:", {'result': result})
    
    def log_plugin_error(self, plugin_name: str, method: str, error: Exception, execution_time: float):
        """Log plugin method error."""
        error_type = type(error).__name__
        error_msg = str(error)[:100]
        
        self.log('basic', f"Plugin error: {plugin_name}.{method} -> {error_type}: {error_msg} ({execution_time:.3f}s)")
    
    def _summarize_result(self, result: Any) -> str:
        """Create a summary of the result for logging."""
        if result is None:
            return "None"
        elif isinstance(result, dict):
            return f"dict({len(result)} keys)"
        elif isinstance(result, list):
            return f"list({len(result)} items)"
        elif isinstance(result, str):
            return f"str({len(result)} chars)"
        elif isinstance(result, bool):
            return str(result)
        else:
            return f"{type(result).__name__}({result})"
    
    def log_analysis_start(self, target: str, analysis_type: str):
        """Log start of analysis."""
        self.log('basic', f"Starting {analysis_type} analysis for: {target}")
    
    def log_analysis_complete(self, target: str, analysis_type: str, total_time: float, plugins_used: int):
        """Log completion of analysis."""
        self.log('basic', f"Completed {analysis_type} analysis for {target}: {plugins_used} plugins, {total_time:.3f}s total")
    
    def log_config_info(self):
        """Log current configuration in debug mode."""
        if not config.is_debug_mode():
            return
            
        debug_info = {
            'debug_level': config.get_debug_level(),
            'active_plugins_allowed': config.allow_active_plugins(),
            'request_timeout': config.get_request_timeout(),
            'passive_only_mode': config.get_passive_only_mode()
        }
        
        self.log('detailed', "Current configuration:", debug_info)


def debug_plugin_method(func: Callable) -> Callable:
    """
    Decorator to add debug logging to plugin methods.
    
    This decorator logs plugin method calls, results, and errors
    when debug mode is enabled.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not config.is_debug_mode():
            return func(self, *args, **kwargs)
        
        plugin_name = getattr(self, 'name', self.__class__.__name__)
        method_name = func.__name__
        
        debug_logger.log_plugin_call(plugin_name, method_name, args, kwargs)
        
        start_time = time.time()
        try:
            result = func(self, *args, **kwargs)
            execution_time = time.time() - start_time
            debug_logger.log_plugin_result(plugin_name, method_name, result, execution_time)
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            debug_logger.log_plugin_error(plugin_name, method_name, e, execution_time)
            raise
    
    return wrapper


# Global debug logger instance
debug_logger = DebugLogger()