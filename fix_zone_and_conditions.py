#!/usr/bin/env python3
"""
Fix zone AND condition issues in Rules 39,40,41,47,50,58
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def fix_zone_and_conditions():
    """Fix zone AND conditions for the 6 problematic rules"""
    
    with app.app_context():
        # Rules that need fixing
        problematic_rules = [39, 40, 41, 47, 50, 58]
        
        for rule_id in problematic_rules:
            rule = ComplianceRule.query.get(rule_id)
            if not rule:
                print(f"❌ Rule {rule_id} not found")
                continue
                
            print(f"\n=== Fixing Rule {rule_id}: {rule.rule_name} ===")
            
            try:
                rule_data = json.loads(rule.value)
                
                # Extract core conditions (non-zone conditions)
                core_conditions = []
                zone_conditions = []
                
                # Parse current structure to separate core and zone conditions
                for condition in rule_data.get('conditions', []):
                    if isinstance(condition, dict):
                        if 'field' in condition and str(condition.get('field', '')).endswith('_zone'):
                            zone_conditions.append(condition)
                        elif 'logic' in condition and 'conditions' in condition:
                            # This is a nested logic group, likely containing zones
                            # Extract zones from nested structure
                            nested_zones = extract_zones_from_nested(condition)
                            if nested_zones:
                                zone_conditions.extend(nested_zones)
                            else:
                                core_conditions.append(condition)
                        else:
                            core_conditions.append(condition)
                
                # Create proper AND structure
                new_rule_structure = {
                    "logic": "AND",
                    "conditions": core_conditions + [
                        {
                            "logic": "OR",
                            "conditions": [
                                {"logic": "AND", "conditions": []},  # Applies to all zones
                                {"logic": "AND", "conditions": zone_conditions}  # Specific zone combinations
                            ]
                        }
                    ]
                }
                
                # Update the rule
                rule.value = json.dumps(new_rule_structure, indent=2)
                db.session.commit()
                
                print("✅ Fixed zone AND conditions")
                
            except Exception as e:
                print(f"❌ Error fixing rule {rule_id}: {e}")
                db.session.rollback()

def extract_zones_from_nested(condition):
    """Extract zone conditions from nested logic structure"""
    zones = []
    if isinstance(condition, dict):
        if 'conditions' in condition:
            for sub_condition in condition['conditions']:
                if isinstance(sub_condition, dict) and 'field' in sub_condition:
                    if str(sub_condition.get('field', '')).endswith('_zone'):
                        zones.append(sub_condition)
                elif isinstance(sub_condition, dict) and 'conditions' in sub_condition:
                    zones.extend(extract_zones_from_nested(sub_condition))
    return zones

if __name__ == '__main__':
    fix_zone_and_conditions()