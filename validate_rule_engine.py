#!/usr/bin/env python3
"""
Validate entire rule engine for zone-based AND conditions
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule

def validate_rule_engine():
    """Validate all compliance rules for zone-based AND conditions"""
    
    with app.app_context():
        rules = ComplianceRule.query.filter(ComplianceRule.is_active == True).all()
        print(f'🎯 Total active compliance rules: {len(rules)}')
        
        zone_compliant_rules = 0
        zone_issues_found = []
        
        for rule in rules:
            print(f'\n=== Rule {rule.id}: {rule.rule_name} ===')
            print(f'Description: {rule.description}')
            print(f'Operator: {rule.operator}')
            print(f'Field: {rule.field_to_check}')
            
            # Check if rule uses composite logic with zones
            if rule.operator == 'composite':
                try:
                    rule_data = json.loads(rule.value)
                    has_zones = check_for_zones(rule_data)
                    print(f'Contains zone conditions: {has_zones}')
                    
                    if has_zones:
                        print('✅ Zone-based logic detected')
                        zone_compliant_rules += 1
                        
                        # Check if zones are properly ANDed with other conditions
                        and_conditions = check_and_conditions(rule_data)
                        if and_conditions:
                            print('✅ Zones are properly ANDed with other conditions')
                        else:
                            print('⚠️  Zones may not be properly ANDed')
                            zone_issues_found.append(f"Rule {rule.id}: Zones not properly ANDed")
                    else:
                        print('⚠️  No zone conditions found')
                        
                except json.JSONDecodeError:
                    print('❌ Invalid JSON in rule value')
                    zone_issues_found.append(f"Rule {rule.id}: Invalid JSON")
            else:
                # Check if it's a zone field
                if str(rule.field_to_check).endswith('_zone'):
                    print('✅ Direct zone field check')
                    zone_compliant_rules += 1
                else:
                    print('⚠️  No zone logic detected')
        
        print(f'\n📊 VALIDATION SUMMARY:')
        print(f'Total rules: {len(rules)}')
        print(f'Zone-compliant rules: {zone_compliant_rules}')
        print(f'Rules without zone logic: {len(rules) - zone_compliant_rules}')
        
        if zone_issues_found:
            print(f'\n❌ Issues found:')
            for issue in zone_issues_found:
                print(f'  - {issue}')
        else:
            print('\n✅ All zone-based rules are properly configured!')
        
        return zone_compliant_rules, len(rules) - zone_compliant_rules, zone_issues_found

def check_for_zones(data):
    """Recursively check if data contains zone conditions"""
    if isinstance(data, dict):
        if 'field' in data and str(data.get('field', '')).endswith('_zone'):
            return True
        for key, value in data.items():
            if check_for_zones(value):
                return True
    elif isinstance(data, list):
        for item in data:
            if check_for_zones(item):
                return True
    return False

def check_and_conditions(data):
    """Check if zones are properly ANDed with other conditions"""
    if isinstance(data, dict):
        logic = data.get('logic', 'AND')
        conditions = data.get('conditions', [])
        
        if logic == 'AND' and conditions:
            # Check if any condition is zone-related
            has_zone = any(str(c.get('field', '')).endswith('_zone') for c in conditions if isinstance(c, dict))
            has_non_zone = any(not str(c.get('field', '')).endswith('_zone') for c in conditions if isinstance(c, dict))
            return has_zone and has_non_zone
        
        # Check nested conditions
        for key, value in data.items():
            if key == 'conditions' and isinstance(value, list):
                for condition in value:
                    if check_and_conditions(condition):
                        return True
    return False

if __name__ == "__main__":
    validate_rule_engine()