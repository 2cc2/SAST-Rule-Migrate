import yaml
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ConfigLoader:
    def __init__(self, config_path="./config.yaml"):
        self.config_path = config_path
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML file."""
        with open(self.config_path, "r") as file:
            self.config_data = yaml.safe_load(file)