# This file is part of FireFind Project.
#
# Copyright (C) 2025 Your Name
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


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
        """Return all vendor names (e.g., 'fortinet', 'sophos')."""
        return list(self.data["vendor_mappings"].keys())

    def vendor_detection_headers(self, vendor):
        """Return set of headers used to auto-detect this vendor."""
        vm = self.data["vendor_mappings"][vendor]
        return set(h.lower() for h in vm.get("detect_headers_any", []))

    def vendor_column_aliases(self, vendor):
        """
        Return column mappings for a given vendor.
        Example: {"id": "Seq #", "srcaddr": "Source", "dstaddr": "Destination"}
        """
        return self.data["vendor_mappings"][vendor]["columns"]

    def vendor_defaults(self, vendor):
        """Return any default values configured for this vendor."""
        return self.data["vendor_mappings"][vendor].get("defaults", {})

    # ---- NEW: helper for risk rating + comments ----
    # ---- These new vendor comments and risk ratings will be shown in the reports later ---
    
    def vendor_extra_fields(self, vendor):
        """
        Return extra optional fields that can be merged later in reporting.
        Example: {"comment": "TL Comment", "risk_rating": "Risk Rating"}
        """
        return self.data["vendor_mappings"][vendor].get("extra_fields", {})


def load_config(path="config/rules_config.json"):
    return Config(path)
