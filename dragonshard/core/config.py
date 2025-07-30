#!/usr/bin/env python3
"""
Configuration management for DragonShard.
Consolidates common configuration patterns and settings.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Set up logging
logger = logging.getLogger(__name__)


class DragonShardConfig:
    """Central configuration management for DragonShard."""

    # Default configuration values
    DEFAULTS = {
        # Scanner settings
        "scanner": {
            "timeout": 30,
            "max_retries": 3,
            "common_ports": [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                143,
                443,
                993,
                995,
                3306,
                3389,
                5432,
                8080,
                8443,
            ],
            "udp_ports": [53, 67, 68, 69, 123, 137, 138, 139, 161, 162, 389, 636, 1433, 1521, 5432],
        },
        # Crawler settings
        "crawler": {
            "max_depth": 3,
            "max_pages": 50,
            "timeout": 10,
            "delay": 0.1,
            "user_agent": "DragonShard/1.0",
            "force_js": False,
        },
        # Fuzzer settings
        "fuzzer": {
            "timeout": 10,
            "delay": 0.1,
            "max_retries": 3,
            "concurrent_requests": 5,
            "payload_file": "data/payloads.json",
        },
        # Genetic algorithm settings
        "genetic": {
            "population_size": 50,
            "mutation_rate": 0.1,
            "crossover_rate": 0.8,
            "max_generations": 100,
            "elite_size": 5,
            "tournament_size": 3,
        },
        # Executor settings
        "executor": {
            "max_concurrent_chains": 5,
            "session_timeout": 300,
            "retry_attempts": 3,
            "retry_delay": 5,
        },
        # Web interface settings
        "web": {
            "host": "0.0.0.0",
            "port": 8000,
            "debug": False,
            "workers": 4,
        },
        # Logging settings
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": None,
        },
        # Test settings
        "test": {
            "target_timeout": 30,
            "container_timeout": 60,
            "exclude_problematic_targets": True,
        },
    }

    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration."""
        self.config_file = config_file or self._get_default_config_path()
        self.config = self._load_config()
        self._setup_logging()

    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        # Look for config in current directory, then in dragonshard directory
        possible_paths = [
            "dragonshard_config.json",
            "config.json",
            os.path.join(os.path.dirname(__file__), "..", "config.json"),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # Return a default path if no config file exists
        return "dragonshard_config.json"

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    file_config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
                return self._merge_config(self.DEFAULTS, file_config)
            except Exception as e:
                logger.warning(f"Failed to load config file {self.config_file}: {e}")
                logger.info("Using default configuration")
                return self.DEFAULTS.copy()
        else:
            logger.info("No config file found, using default configuration")
            return self.DEFAULTS.copy()

    def _merge_config(
        self, defaults: Dict[str, Any], user_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge user configuration with defaults."""
        merged = defaults.copy()

        def merge_dict(base: Dict[str, Any], update: Dict[str, Any]) -> None:
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value

        merge_dict(merged, user_config)
        return merged

    def _setup_logging(self):
        """Set up logging based on configuration."""
        log_config = self.config.get("logging", {})
        level = getattr(logging, log_config.get("level", "INFO").upper())
        format_str = log_config.get(
            "format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        logging.basicConfig(
            level=level,
            format=format_str,
            filename=log_config.get("file"),
        )

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        section_config = self.config.get(section, {})
        return section_config.get(key, default)

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire configuration section."""
        return self.config.get(section, {})

    def set(self, section: str, key: str, value: Any):
        """Set a configuration value."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

    def save(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def reload(self):
        """Reload configuration from file."""
        self.config = self._load_config()
        self._setup_logging()


# Global configuration instance
_config = None


def get_config() -> DragonShardConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = DragonShardConfig()
    return _config


def get_setting(section: str, key: str, default: Any = None) -> Any:
    """Get a configuration setting."""
    return get_config().get(section, key, default)


def get_section(section: str) -> Dict[str, Any]:
    """Get a configuration section."""
    return get_config().get_section(section)
