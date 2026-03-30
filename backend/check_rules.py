#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import NormalizedRule, RawFirewallRule

with app.app_context():
    # Check normalized rules
    rules = NormalizedRule.query.filter_by(is_deleted=False).all()
    print(f'Active normalized rules: {len(rules)}')
    
    for rule in rules[:10]:  # Show first 10 rules
        print(f'\nNormalized Rule ID: {rule.id}')
        print(f'  Rule Name: {rule.rule_name}')
        print(f'  Raw Rule ID: {rule.raw_rule_id}')
        print(f'  Source File: {rule.source_file}')
        
        if rule.raw_rule_id:
            raw_rule = RawFirewallRule.query.get(rule.raw_rule_id)
            if raw_rule:
                print(f'  Raw Rule Name: {raw_rule.rule_name}')
                print(f'  Raw Rule Text: {raw_rule.raw_text[:100]}...')
            else:
                print(f'  Raw Rule: Not found (ID: {rule.raw_rule_id})')
        else:
            print(f'  No associated raw rule')

    # Also check raw rules
    raw_rules = RawFirewallRule.query.all()
    print(f'\n\nActive raw rules: {len(raw_rules)}')
    
    for raw_rule in raw_rules[:5]:  # Show first 5 raw rules
        print(f'\nRaw Rule ID: {raw_rule.id}')
        print(f'  Rule Name: {raw_rule.rule_name}')
        print(f'  Raw Text: {raw_rule.raw_text[:100]}...')