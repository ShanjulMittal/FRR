#!/usr/bin/env python3
"""
Check the uploaded rules to verify that port information was properly extracted
"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from app import app
from models import db, RawFirewallRule, NormalizedRule

def check_uploaded_rules():
    """Check the uploaded rules to verify port extraction"""
    
    with app.app_context():
        # Get the most recent upload
        latest_rules = RawFirewallRule.query.order_by(RawFirewallRule.id.desc()).limit(10).all()
        
        print("=== LATEST RAW RULES (most recent first) ===")
        for rule in latest_rules:
            print(f"ID: {rule.id}, Source File: {rule.source_file}")
            print(f"  Protocol: {rule.protocol}, Source Port: {rule.source_port}, Dest Port: {rule.dest_port}")
            print(f"  Raw Text: {rule.raw_text[:100]}...")
            print("---")
        
        # Check normalized rules
        latest_normalized = NormalizedRule.query.order_by(NormalizedRule.id.desc()).limit(10).all()
        
        print("\n=== LATEST NORMALIZED RULES (most recent first) ===")
        for rule in latest_normalized:
            print(f"ID: {rule.id}, Source File: {rule.source_file}")
            print(f"  Protocol: {rule.protocol}, Source Port: {rule.source_port}, Dest Port: {rule.dest_port}")
            print(f"  Service Name: {rule.service_name}")
            print("---")
        
        # Count rules from observations.csv
        obs_raw_count = RawFirewallRule.query.filter_by(source_file='observations.csv').count()
        obs_norm_count = NormalizedRule.query.filter_by(source_file='observations.csv').count()
        
        print(f"\n=== RULE COUNTS FOR observations.csv ===")
        print(f"Raw rules: {obs_raw_count}")
        print(f"Normalized rules: {obs_norm_count}")
        
        # Check if any rules have dest_port populated
        rules_with_dest_port = NormalizedRule.query.filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.dest_port.isnot(None)
        ).count()
        
        print(f"Normalized rules with dest_port populated: {rules_with_dest_port}")
        
        # Show some examples of rules with dest_port
        port_examples = NormalizedRule.query.filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.dest_port.isnot(None)
        ).limit(5).all()
        
        print(f"\n=== EXAMPLES OF RULES WITH DEST_PORT ===")
        for rule in port_examples:
            print(f"Dest Port: {rule.dest_port}, Protocol: {rule.protocol}, Service: {rule.service_name}")

if __name__ == "__main__":
    check_uploaded_rules()