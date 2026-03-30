#!/usr/bin/env python3

import sys
sys.path.append('/Users/shanjulmittal/FRR')
sys.path.append('/Users/shanjulmittal/FRR/backend')

from backend.models import ComplianceRule
from backend.app import app
import json

def check_rule_structure(rule_id):
    with app.app_context():
        rule = ComplianceRule.query.get(rule_id)
        if rule:
            rule_data = json.loads(rule.value)
            print(f'Rule {rule_id} ({rule.rule_name}) structure:')
            print(json.dumps(rule_data, indent=2))
            return rule_data
        else:
            print(f'Rule {rule_id} not found')
            return None

if __name__ == '__main__':
    check_rule_structure(39)