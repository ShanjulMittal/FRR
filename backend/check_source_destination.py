#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, NormalizedRule, RawFirewallRule

def check_source_destination():
    with app.app_context():
        print("=== CHECKING SOURCE AND DESTINATION FIELDS ===")
        
        # Get normalized rules from observations.csv
        normalized_rules = NormalizedRule.query.filter_by(source_file='observations.csv').all()
        print(f"Found {len(normalized_rules)} normalized rules")
        
        # Check first 10 rules
        for i, rule in enumerate(normalized_rules[:10]):
            print(f"\nRule {i+1}:")
            print(f"  Rule Name: {rule.rule_name}")
            print(f"  Source IP: {rule.source_ip}")
            print(f"  Source Environment: {rule.source_environment}")
            print(f"  Source Owner: {rule.source_owner}")
            print(f"  Source Hostname: {rule.source_hostname}")
            print(f"  Dest IP: {rule.dest_ip}")
            print(f"  Dest Environment: {rule.dest_environment}")
            print(f"  Dest Hostname: {rule.dest_hostname}")
            
            # Also check the raw rule for source/destination
            if rule.raw_rule_id:
                raw_rule = RawFirewallRule.query.get(rule.raw_rule_id)
                if raw_rule:
                    print(f"  Raw Rule Source: {raw_rule.source}")
                    print(f"  Raw Rule Destination: {raw_rule.destination}")
                else:
                    print(f"  Raw Rule: Not found")
            else:
                print(f"  No raw rule ID")

if __name__ == "__main__":
    check_source_destination()