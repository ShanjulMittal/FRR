#!/usr/bin/env python3
"""
Comprehensive fix for zone AND conditions in all problematic rules
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def fix_all_zone_and_conditions():
    """Fix zone AND conditions for all problematic rules"""
    
    with app.app_context():
        # Rules that need fixing
        problematic_rules = [39, 40, 41, 47, 50, 58, 59]
        
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
                
                # Parse current structure
                for condition in rule_data.get('conditions', []):
                    if isinstance(condition, dict):
                        if 'field' in condition and str(condition.get('field', '')).endswith('_zone'):
                            zone_conditions.append(condition)
                        elif 'logic' in condition and 'conditions' in condition:
                            # This is a nested logic group
                            if condition.get('logic') == 'OR' and len(condition.get('conditions', [])) == 2:
                                # This looks like our zone OR group, extract zones from it
                                for or_condition in condition['conditions']:
                                    if isinstance(or_condition, dict) and or_condition.get('logic') == 'AND':
                                        for and_condition in or_condition.get('conditions', []):
                                            if isinstance(and_condition, dict) and str(and_condition.get('field', '')).endswith('_zone'):
                                                zone_conditions.append(and_condition)
                            else:
                                # Keep other nested logic as core
                                core_conditions.append(condition)
                        else:
                            core_conditions.append(condition)
                
                # If no zones found, create default zone conditions
                if not zone_conditions:
                    zone_conditions = [
                        {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                        {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                    ]
                
                # Create proper AND structure with zones properly integrated at the same level
                # This ensures zone and non-zone conditions are ANDed together directly
                all_conditions = core_conditions + zone_conditions
                
                new_rule_structure = {
                    "logic": "AND",
                    "conditions": all_conditions
                }
                
                # Update the rule
                rule.value = json.dumps(new_rule_structure, indent=2)
                db.session.commit()
                
                print("✅ Fixed zone AND conditions")
                
            except Exception as e:
                print(f"❌ Error fixing rule {rule_id}: {e}")
                import traceback
                traceback.print_exc()
                db.session.rollback()

if __name__ == '__main__':
    fix_all_zone_and_conditions()