#!/usr/bin/env python3
"""
Fix Rule 59's zone AND condition logic to properly integrate with other conditions
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def fix_rule_59_and_conditions():
    """Fix Rule 59 to properly AND zone conditions with other conditions"""
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        # Create a rule structure that properly ANDs all conditions including zones
        new_rule_structure = {
            "logic": "AND",
            "conditions": [
                {"field": "action", "operator": "equals", "value": "permit"},
                {"field": "source_ip", "operator": "equals", "value": "any"},
                {"field": "dest_ip", "operator": "not_equals", "value": "any"},
                {"field": "dest_ip", "operator": "is_not_empty", "value": ""},
                {"field": "protocol", "operator": "not_equals", "value": "icmp"},
                {"field": "application", "operator": "not_equals", "value": "ping6"},
                {
                    "logic": "OR",
                    "conditions": [
                        {"field": "service_port", "operator": "equals", "value": "any"},
                        {"field": "service_port", "operator": "is_empty", "value": ""},
                        {"field": "service_port", "operator": "regex_match", "value": "^(\\*|any|all|0\\s*-\\s*65535|1\\s*-\\s*65535)$"},
                        {"field": "dest_port", "operator": "equals", "value": "any"},
                        {"field": "dest_port", "operator": "is_empty", "value": ""},
                        {"field": "dest_port", "operator": "regex_match", "value": "^(\\*|any|all|0\\s*-\\s*65535|1\\s*-\\s*65535)$"},
                        {"field": "protocol", "operator": "in_list", "value": "any,ip,*"}
                    ]
                }
            ]
        }
        
        rule59.value = json.dumps(new_rule_structure)
        rule59.description = "Disallow permit with any source and unrestricted service, excluding ICMP/IPv6 infrastructure"
        db.session.commit()
        
        print("✅ Rule 59 AND conditions fixed successfully!")
        print("New description:", rule59.description)

if __name__ == "__main__":
    fix_rule_59_and_conditions()