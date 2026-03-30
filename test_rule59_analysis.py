#!/usr/bin/env python3
"""
Test script to analyze Rule 59 behavior and identify why the finding is incorrect.
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

import json
from app import app
from models import ComplianceRule, db
from compliance_engine import compliance_engine

class DummyRule:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        if not hasattr(self, 'custom_fields_data'):
            self.custom_fields_data = None
        if not hasattr(self, 'raw_rule'):
            self.raw_rule = None

def test_rule59_scenarios():
    """Test various scenarios to understand Rule 59 behavior"""
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        print("🔍 Analyzing Rule 59: 'Permit + Any Source + Specific Dest + Any Service'")
        print(f"Rule Description: {rule59.description}")
        print(f"Rule Severity: {rule59.severity}")
        print(f"Rule Active: {rule59.is_active}")
        print()
        
        # Parse the composite logic
        try:
            rule_logic = json.loads(rule59.value)
            print("📋 Rule Logic Structure:")
            print(json.dumps(rule_logic, indent=2))
            print()
        except Exception as e:
            print(f"❌ Error parsing rule logic: {e}")
            return
        
        # Test scenarios that should VIOLATE Rule 59
        print("🧪 Testing Scenarios that SHOULD Violate Rule 59:")
        print("=" * 60)
        
        # Scenario 1: The classic violation case
        print("1. Classic violation: permit + any source + specific dest + any service")
        rule1 = DummyRule(
            action='permit',
            source_ip='any',
            dest_ip='192.168.1.100',  # Specific destination
            service_port='any',
            dest_port='',
            protocol='ip'
        )
        result1 = compliance_engine.evaluate_rule_against_compliance(rule1, rule59)
        print(f"   Result: {'VIOLATION' if not result1['compliant'] else 'PASS'}")
        print(f"   Expected: VIOLATION")
        if result1['violation_details']:
            print(f"   Details: {result1['violation_details']}")
        print()
        
        # Scenario 2: Specific destination with empty service
        print("2. Specific dest with empty service")
        rule2 = DummyRule(
            action='permit',
            source_ip='any',
            dest_ip='10.0.0.50',  # Specific destination
            service_port='',  # Empty service
            dest_port='',     # Empty dest port
            protocol='tcp'
        )
        result2 = compliance_engine.evaluate_rule_against_compliance(rule2, rule59)
        print(f"   Result: {'VIOLATION' if not result2['compliant'] else 'PASS'}")
        print(f"   Expected: VIOLATION")
        if result2['violation_details']:
            print(f"   Details: {result2['violation_details']}")
        print()
        
        # Scenario 3: Specific destination with service range (0-65535)
        print("3. Specific dest with full port range (0-65535)")
        rule3 = DummyRule(
            action='permit',
            source_ip='any',
            dest_ip='172.16.0.25',  # Specific destination
            service_port='0-65535',  # Full range = any
            dest_port='0-65535',     # Full range = any
            protocol='udp'
        )
        result3 = compliance_engine.evaluate_rule_against_compliance(rule3, rule59)
        print(f"   Result: {'VIOLATION' if not result3['compliant'] else 'PASS'}")
        print(f"   Expected: VIOLATION")
        if result3['violation_details']:
            print(f"   Details: {result3['violation_details']}")
        print()
        
        # Test scenarios that should PASS Rule 59 (not violate)
        print("🧪 Testing Scenarios that SHOULD Pass Rule 59:")
        print("=" * 60)
        
        # Scenario 4: Any destination (should not violate)
        print("4. Any destination (should not violate)")
        rule4 = DummyRule(
            action='permit',
            source_ip='any',
            dest_ip='any',  # Any destination
            service_port='80',
            dest_port='80',
            protocol='tcp'
        )
        result4 = compliance_engine.evaluate_rule_against_compliance(rule4, rule59)
        print(f"   Result: {'VIOLATION' if not result4['compliant'] else 'PASS'}")
        print(f"   Expected: PASS")
        if result4['violation_details']:
            print(f"   Details: {result4['violation_details']}")
        print()
        
        # Scenario 5: Specific source (should not violate)
        print("5. Specific source (should not violate)")
        rule5 = DummyRule(
            action='permit',
            source_ip='192.168.1.10',  # Specific source
            dest_ip='192.168.1.100',   # Specific destination
            service_port='any',
            dest_port='',
            protocol='ip'
        )
        result5 = compliance_engine.evaluate_rule_against_compliance(rule5, rule59)
        print(f"   Result: {'VIOLATION' if not result5['compliant'] else 'PASS'}")
        print(f"   Expected: PASS")
        if result5['violation_details']:
            print(f"   Details: {result5['violation_details']}")
        print()
        
        # Scenario 6: Deny action (should not violate)
        print("6. Deny action (should not violate)")
        rule6 = DummyRule(
            action='deny',  # Deny action
            source_ip='any',
            dest_ip='192.168.1.100',  # Specific destination
            service_port='any',
            dest_port='',
            protocol='ip'
        )
        result6 = compliance_engine.evaluate_rule_against_compliance(rule6, rule59)
        print(f"   Result: {'VIOLATION' if not result6['compliant'] else 'PASS'}")
        print(f"   Expected: PASS")
        if result6['violation_details']:
            print(f"   Details: {result6['violation_details']}")
        print()
        
        # Summary
        print("📊 Summary:")
        print("=" * 60)
        violations_expected = [False, False, False]  # Scenarios 1-3 should violate
        passes_expected = [True, True, True]         # Scenarios 4-6 should pass
        
        results = [
            not result1['compliant'],  # Should be True (violate)
            not result2['compliant'],  # Should be True (violate)
            not result3['compliant'],  # Should be True (violate)
            not result4['compliant'],  # Should be False (pass)
            not result5['compliant'],  # Should be False (pass)
            not result6['compliant']   # Should be False (pass)
        ]
        
        expected = [False, False, False, True, True, True]
        
        for i, (actual, expect) in enumerate(zip(results, expected)):
            status = "✅ CORRECT" if actual == expect else "❌ INCORRECT"
            scenario = f"Scenario {i+1}"
            print(f"{scenario}: {status}")
        
        print()
        print("🔍 If any scenarios show 'INCORRECT', Rule 59 has a logic issue!")

if __name__ == '__main__':
    test_rule59_scenarios()