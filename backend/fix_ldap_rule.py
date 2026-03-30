
import json
from app import app, db
from models import ComplianceRule

def fix_ldap_rule():
    with app.app_context():
        # Find the LDAP rule
        rule = ComplianceRule.query.filter(
            ComplianceRule.rule_name.ilike('%Unsecured LDAP (389)%')
        ).first()
        
        if not rule:
            print("LDAP rule not found!")
            return
            
        print(f"Updating Rule {rule.id}: {rule.rule_name}")
        print(f"Old Value: {rule.value}")
        
        # Parse existing JSON
        try:
            rule_def = json.loads(rule.value)
        except json.JSONDecodeError:
            print("Error parsing rule JSON")
            return

        # Update conditions
        # We know the structure is:
        # {
        #   "logic": "AND", 
        #   "conditions": [
        #     {"field": "action", "operator": "equals", "value": "permit"}, 
        #     {"logic": "OR", "conditions": [
        #       {"field": "dest_port", "operator": "contains", "value": "389"}, 
        #       {"field": "service_port", "operator": "contains", "value": "389"}
        #     ]}
        #   ]
        # }
        
        # Traverse and update
        for cond in rule_def.get('conditions', []):
            if cond.get('logic') == 'OR':
                for sub_cond in cond.get('conditions', []):
                    if sub_cond.get('value') == '389' and sub_cond.get('operator') == 'contains':
                        print(f"Fixing condition: {sub_cond}")
                        sub_cond['operator'] = 'regex_match'
                        sub_cond['value'] = r'\b389\b'
                        print(f"Fixed condition: {sub_cond}")
        
        # Save back
        rule.value = json.dumps(rule_def)
        db.session.commit()
        print(f"New Value: {rule.value}")
        print("Rule updated successfully!")

if __name__ == '__main__':
    fix_ldap_rule()
