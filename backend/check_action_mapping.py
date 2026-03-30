#!/usr/bin/env python3

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import RawFirewallRule, NormalizedRule, db

def check_action_mapping():
    """Check if action field is correctly mapped and populated"""
    
    # Check raw rules
    raw_rules = RawFirewallRule.query.all()
    print(f"Total raw rules: {len(raw_rules)}")
    
    # Check action field in raw rules
    action_values = {}
    for rule in raw_rules:
        action = rule.action
        if action:
            action_values[action] = action_values.get(action, 0) + 1
    
    print("\nAction values in RawFirewallRule:")
    for action, count in action_values.items():
        print(f"  {action}: {count} rules")
    
    # Check normalized rules
    normalized_rules = NormalizedRule.query.all()
    print(f"\nTotal normalized rules: {len(normalized_rules)}")
    
    # Check action field in normalized rules
    action_values_norm = {}
    for rule in normalized_rules:
        action = rule.action
        if action:
            action_values_norm[action] = action_values_norm.get(action, 0) + 1
    
    print("\nAction values in NormalizedRule:")
    for action, count in action_values_norm.items():
        print(f"  {action}: {count} rules")
    
    # Show first 10 rules with action values
    print("\nFirst 10 raw rules with action values:")
    for i, rule in enumerate(raw_rules[:10]):
        print(f"Rule {i+1}: Action='{rule.action}', Rule Name='{rule.rule_name}'")
    
    print("\nFirst 10 normalized rules with action values:")
    for i, rule in enumerate(normalized_rules[:10]):
        print(f"Rule {i+1}: Action='{rule.action}', Rule Name='{rule.rule_name}'")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        check_action_mapping()