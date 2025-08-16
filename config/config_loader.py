# config/config_loader.py
import json
from pathlib import Path

class Config:
    def __init__(self, path="config/rules_config.json"):
        self.path = Path(path)
        with self.path.open("r", encoding="utf-8") as f:
            self.data = json.load(f)

    # ---- sections ----
    def risk_rules(self):
        return self.data["risk_rules"]

    def reporting_style(self):
        return self.data.get("reporting", {})

    # ---- vendor helpers ----
    def vendor_keys(self):
        return list(self.data["vendor_mappings"].keys())

    def vendor_detection_headers(self, vendor):
        vm = self.data["vendor_mappings"][vendor]
        return set(h.lower() for h in vm.get("detect_headers_any", []))

    def vendor_column_aliases(self, vendor):
        return self.data["vendor_mappings"][vendor]["columns"]

    def vendor_defaults(self, vendor):
        return self.data["vendor_mappings"][vendor].get("defaults", {})

def load_config(path="config/rules_config.json"):
    return Config(path)
