
import json
from app import app
from models import ComplianceRule, NormalizedRule
from compliance_engine import ComplianceEngine

def verify_ldap_fix():
    with app.app_context():
        # Fetch the LDAP rule
        rule = ComplianceRule.query.filter(
            ComplianceRule.rule_name.ilike('%Unsecured LDAP (389)%')
        ).first()
        
        if not rule:
            print("LDAP rule not found!")
            return

        print(f"Testing Rule {rule.id}: {rule.rule_name}")
        print(f"Value: {rule.value}")
        
        engine = ComplianceEngine()
        
        # Test Case 1: Port 3389 (Should be COMPLIANT/PASS because it's NOT 389)
        # The rule logic is: Violation = (Action != disabled) AND (dest_port == 389 OR service_port == 389)
        # Wait, let's check the rule logic again.
        # Rule Value: {"logic": "AND", "conditions": [{"field": "action", "operator": "equals", "value": "permit"}, {"logic": "OR", "conditions": [{"field": "dest_port", "operator": "regex_match", "value": "\\b389\\b"}, {"field": "service_port", "operator": "regex_match", "value": "\\b389\\b"}]}]}
        # If match -> Violation (assuming violation_mode=True)
        
        # Case 1: Port 3389 (Should NOT match regex -> Should be Compliant)
        r1 = NormalizedRule(
            action='permit',
            dest_port='3389',
            service_port='3389'
        )
        res1 = engine.evaluate_rule_against_compliance(r1, rule)
        print(f"Test 3389: {'COMPLIANT' if res1['compliant'] else 'VIOLATION'}")
        
        # Case 2: Port 3890 (Should NOT match regex -> Should be Compliant)
        r2 = NormalizedRule(
            action='permit',
            dest_port='3890',
            service_port='3890'
        )
        res2 = engine.evaluate_rule_against_compliance(r2, rule)
        print(f"Test 3890: {'COMPLIANT' if res2['compliant'] else 'VIOLATION'}")

        # Case 3: Port 389 (Should MATCH regex -> Should be Violation)
        r3 = NormalizedRule(
            action='permit',
            dest_port='389',
            service_port='389'
        )
        res3 = engine.evaluate_rule_against_compliance(r3, rule)
        print(f"Test 389: {'COMPLIANT' if res3['compliant'] else 'VIOLATION'}")
        
        # Case 4: Port 389 mixed (Should MATCH regex -> Should be Violation)
        r4 = NormalizedRule(
            action='permit',
            dest_port='80, 389, 443',
            service_port='80, 389, 443'
        )
        res4 = engine.evaluate_rule_against_compliance(r4, rule)
        print(f"Test 389 mixed: {'COMPLIANT' if res4['compliant'] else 'VIOLATION'}")

if __name__ == '__main__':
    verify_ldap_fix()
