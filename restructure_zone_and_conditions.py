#!/usr/bin/env python3
"""
Complete restructure of zone AND conditions for proper integration
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def restructure_zone_and_conditions():
    """Completely restructure zone AND conditions for proper integration"""
    
    with app.app_context():
        # Rules that need fixing
        problematic_rules = [39, 40, 41, 47, 50, 58, 59]
        
        for rule_id in problematic_rules:
            rule = ComplianceRule.query.get(rule_id)
            if not rule:
                print(f"❌ Rule {rule_id} not found")
                continue
                
            print(f"\n=== Restructuring Rule {rule_id}: {rule.rule_name} ===")
            
            try:
                rule_data = json.loads(rule.value)
                
                # Extract all core conditions (non-zone conditions)
                core_conditions = []
                
                # Parse current structure to extract core conditions
                for condition in rule_data.get('conditions', []):
                    if isinstance(condition, dict):
                        if 'field' in condition and not str(condition.get('field', '')).endswith('_zone'):
                            # This is a core condition (not zone-related)
                            core_conditions.append(condition)
                        elif 'logic' in condition and 'conditions' in condition:
                            # This is a nested logic group - check if it's zone-related
                            if not is_zone_logic_group(condition):
                                core_conditions.append(condition)
                
                # Create the proper AND structure
                # The rule should be: (core_conditions) AND (zone_conditions OR applies_to_all_zones)
                new_rule_structure = {
                    "logic": "AND",
                    "conditions": [
                        # First group: all core conditions must be true
                        {
                            "logic": "AND",
                            "conditions": core_conditions
                        },
                        # Second group: either applies to all zones OR specific zone combination
                        {
                            "logic": "OR",
                            "conditions": [
                                {
                                    "logic": "AND",
                                    "conditions": []  # Empty means applies to all zones
                                },
                                {
                                    "logic": "AND",
                                    "conditions": [
                                        {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                                        {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
                
                # Update the rule
                rule.value = json.dumps(new_rule_structure, indent=2)
                db.session.commit()
                
                print("✅ Successfully restructured zone AND conditions")
                
            except Exception as e:
                print(f"❌ Error restructuring rule {rule_id}: {e}")
                import traceback
                traceback.print_exc()
                db.session.rollback()

def is_zone_logic_group(condition):
    """Check if a logic group contains only zone conditions"""
    if not isinstance(condition, dict) or 'conditions' not in condition:
        return False
    
    for sub_condition in condition.get('conditions', []):
        if isinstance(sub_condition, dict):
            if 'field' in sub_condition and not str(sub_condition.get('field', '')).endswith('_zone'):
                return False
            elif 'logic' in sub_condition:
                if not is_zone_logic_group(sub_condition):
                    return False
    
    return True

if __name__ == '__main__':
    restructure_zone_and_conditions()