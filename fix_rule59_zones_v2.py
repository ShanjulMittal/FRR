#!/usr/bin/env python3
"""
Script to fix Rule 59 zone logic to be more targeted and precise
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import db, ComplianceRule
import json

def fix_rule_59_zone_logic():
    """Fix Rule 59 zone logic to be more precise and targeted"""
    
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        print("Fixing Rule 59 zone logic...")
        
        # Create new JSON structure with refined zone conditions
        new_rule_structure = {
            "logic": "AND",
            "conditions": [
                {
                    "field": "action",
                    "operator": "equals", 
                    "value": "permit"
                },
                {
                    "field": "source_ip",
                    "operator": "equals",
                    "value": "any"
                },
                {
                    "field": "dest_ip",
                    "operator": "not_equals",
                    "value": "any"
                },
                {
                    "field": "dest_ip",
                    "operator": "is_not_empty",
                    "value": ""
                },
                # Exclude ICMP and ping6 traffic (infrastructure/IPv6 connectivity)
                {
                    "field": "protocol",
                    "operator": "not_equals",
                    "value": "icmp"
                },
                {
                    "field": "application",
                    "operator": "not_equals",
                    "value": "ping6"
                },
                # REFINED: Only flag rules that have BOTH specific zones AND are high-risk
                {
                    "logic": "AND",
                    "conditions": [
                        {
                            "field": "source_zone",
                            "operator": "equals",
                            "value": "Inbound-Internet"
                        },
                        {
                            "field": "dest_zone", 
                            "operator": "equals",
                            "value": "Ext-WEB-DMZ"
                        }
                    ]
                },
                # Service/port conditions (unchanged)
                {
                    "logic": "OR",
                    "conditions": [
                        {
                            "field": "service_port",
                            "operator": "equals",
                            "value": "any"
                        },
                        {
                            "field": "service_port",
                            "operator": "is_empty",
                            "value": ""
                        },
                        {
                            "field": "service_port",
                            "operator": "regex_match",
                            "value": "^(\\*|any|all|0\\s*-\s*65535|1\\s*-\s*65535)$"
                        },
                        {
                            "field": "dest_port",
                            "operator": "equals",
                            "value": "any"
                        },
                        {
                            "field": "dest_port",
                            "operator": "is_empty",
                            "value": ""
                        },
                        {
                            "field": "dest_port",
                            "operator": "regex_match",
                            "value": "^(\\*|any|all|0\\s*-\s*65535|1\\s*-\s*65535)$"
                        },
                        {
                            "field": "protocol",
                            "operator": "in_list",
                            "value": "any,ip,*"
                        }
                    ]
                }
            ]
        }
        
        # Update the rule
        rule59.value = json.dumps(new_rule_structure)
        rule59.description = "Disallow permit from Inbound-Internet to Ext-WEB-DMZ with any service, excluding ICMP/IPv6 infrastructure"
        
        db.session.commit()
        
        print("\n✅ Rule 59 zone logic fixed successfully!")
        print("New description:", rule59.description)
        print("New JSON structure:")
        print(json.dumps(new_rule_structure, indent=2))
        
        return True

if __name__ == "__main__":
    fix_rule_59_zone_logic()