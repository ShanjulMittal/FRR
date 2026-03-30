#!/usr/bin/env python3
"""
Script to update Rule 59 to include zone-based conditions and exclude ICMP/IPv6 infrastructure traffic
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import db, ComplianceRule
import json

def update_rule_59_with_zones():
    """Update Rule 59 to include source/destination zones and exclude ICMP traffic"""
    
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        print("Current Rule 59:")
        print(f"Name: {rule59.rule_name}")
        print(f"Description: {rule59.description}")
        print(f"Current JSON: {rule59.value}")
        
        # Create new JSON structure with zone conditions and ICMP exclusion
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
                # NEW: Exclude ICMP and ping6 traffic (infrastructure/IPv6 connectivity)
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
                # NEW: Add source zone conditions (AND logic)
                {
                    "logic": "OR",
                    "conditions": [
                        {
                            "field": "source_zone",
                            "operator": "is_empty",
                            "value": ""
                        },
                        {
                            "field": "source_zone",
                            "operator": "not_equals",
                            "value": "Inbound-Internet"
                        }
                    ]
                },
                # NEW: Add destination zone conditions (AND logic)
                {
                    "logic": "OR",
                    "conditions": [
                        {
                            "field": "dest_zone",
                            "operator": "is_empty",
                            "value": ""
                        },
                        {
                            "field": "dest_zone",
                            "operator": "not_equals",
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
        rule59.description = "Disallow permit when source is any and service is any, excluding ICMP/IPv6 infrastructure traffic"
        
        db.session.commit()
        
        print("\n✅ Rule 59 updated successfully!")
        print("New description:", rule59.description)
        print("New JSON structure:")
        print(json.dumps(new_rule_structure, indent=2))
        
        return True

if __name__ == "__main__":
    update_rule_59_with_zones()