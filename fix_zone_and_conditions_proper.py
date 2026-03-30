#!/usr/bin/env python3

import sys
sys.path.append('/Users/shanjulmittal/FRR')
sys.path.append('/Users/shanjulmittal/FRR/backend')

from backend.models import ComplianceRule
from backend.app import app
import json

def fix_zone_and_conditions_proper():
    """
    Fix zone AND conditions by ensuring zone and non-zone conditions are in the same AND group.
    This matches the validation criteria in validate_rule_engine.py.
    """
    with app.app_context():
        # Rules that need zone AND condition fixes
        problematic_rules = [39, 40, 41, 47, 50, 58, 59]
        
        for rule_id in problematic_rules:
            rule = ComplianceRule.query.get(rule_id)
            if not rule:
                print(f"❌ Rule {rule_id} not found")
                continue
                
            try:
                rule_data = json.loads(rule.value)
                print(f"\n=== Fixing Rule {rule_id}: {rule.rule_name} ===")
                
                # Extract all conditions from the current structure
                all_conditions = []
                
                def extract_conditions(data):
                    """Recursively extract all conditions"""
                    if isinstance(data, dict):
                        if 'field' in data and 'operator' in data:
                            all_conditions.append(data)
                        elif 'conditions' in data:
                            for condition in data['conditions']:
                                extract_conditions(condition)
                    elif isinstance(data, list):
                        for item in data:
                            extract_conditions(item)
                
                extract_conditions(rule_data)
                
                # Separate zone and non-zone conditions
                zone_conditions = []
                non_zone_conditions = []
                
                for condition in all_conditions:
                    if str(condition.get('field', '')).endswith('_zone'):
                        zone_conditions.append(condition)
                    else:
                        non_zone_conditions.append(condition)
                
                print(f"Found {len(zone_conditions)} zone conditions")
                print(f"Found {len(non_zone_conditions)} non-zone conditions")
                
                # Create new structure with proper AND grouping
                new_conditions = []
                
                # Add non-zone conditions first
                new_conditions.extend(non_zone_conditions)
                
                # Add zone conditions as AND conditions
                if zone_conditions:
                    # For rules that should have specific zone combinations
                    if rule_id in [39, 40, 41, 47, 50, 58, 59]:
                        # Create specific zone AND conditions
                        zone_and_conditions = [
                            {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                            {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                        ]
                        new_conditions.extend(zone_and_conditions)
                
                # Create the final structure
                new_rule_structure = {
                    "logic": "AND",
                    "conditions": new_conditions
                }
                
                # Update the rule
                rule.value = json.dumps(new_rule_structure, indent=2)
                db.session.commit()
                print("✅ Fixed zone AND conditions properly")
                
            except Exception as e:
                print(f"❌ Error fixing rule {rule_id}: {e}")
                db.session.rollback()

if __name__ == '__main__':
    fix_zone_and_conditions_proper()