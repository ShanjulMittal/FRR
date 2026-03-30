#!/usr/bin/env python3
"""
Restore zone logic to Rule 59 with proper AND conditions
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db

def restore_rule59_zone_logic():
    """Restore zone logic to Rule 59 with proper AND conditions"""
    
    with app.app_context():
        rule = ComplianceRule.query.get(59)
        if not rule:
            print("❌ Rule 59 not found")
            return
            
        print(f"=== Restoring Zone Logic to Rule 59: {rule.rule_name} ===")
        
        try:
            # Get current core conditions
            current_data = json.loads(rule.value)
            core_conditions = []
            
            # Extract core conditions (non-zone conditions)
            for condition in current_data.get('conditions', []):
                if isinstance(condition, dict) and 'field' in condition:
                    # Skip zone fields, keep core conditions
                    if not str(condition.get('field', '')).endswith('_zone'):
                        core_conditions.append(condition)
                elif isinstance(condition, dict) and 'logic' in condition and 'conditions' in condition:
                    # This is the OR group for service ports - keep it as core
                    core_conditions.append(condition)
            
            # Create proper AND structure with zone logic
            new_rule_structure = {
                "logic": "AND",
                "conditions": core_conditions + [
                    {
                        "logic": "OR",
                        "conditions": [
                            {"logic": "AND", "conditions": []},  # Applies to all zones
                            {"logic": "AND", "conditions": [
                                {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                                {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                            ]}
                        ]
                    }
                ]
            }
            
            # Update the rule
            rule.value = json.dumps(new_rule_structure, indent=2)
            db.session.commit()
            
            print("✅ Successfully restored zone logic to Rule 59")
            
        except Exception as e:
            print(f"❌ Error restoring zone logic: {e}")
            db.session.rollback()

if __name__ == '__main__':
    restore_rule59_zone_logic()