#!/usr/bin/env python3
"""
Final fix for Rule 59 - Makes zone conditions optional while maintaining core security checks
"""

import sys
import os
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def fix_rule_59_final():
    """Fix Rule 59 to make zone conditions optional while maintaining security"""
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        # Create a rule structure that makes zone conditions optional
        # The rule will trigger if EITHER:
        # 1. It's a basic permit+any source+specific dest+any service rule (regardless of zones)
        # 2. OR it's specifically from Inbound-Internet to Ext-WEB-DMZ
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
                        # Option 1: Basic rule without zone restrictions
                        {"logic": "AND", "conditions": []},
                        # Option 2: Specific high-risk zone combination
                        {
                            "logic": "AND",
                            "conditions": [
                                {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                                {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                            ]
                        }
                    ]
                },
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
        rule59.description = "Disallow permit with any source and unrestricted service, with optional zone-based filtering for high-risk combinations"
        db.session.commit()
        
        print("✅ Rule 59 final fix applied successfully!")
        print("New description:", rule59.description)

if __name__ == "__main__":
    fix_rule_59_final()