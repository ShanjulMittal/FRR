#!/usr/bin/env python3
"""
Test script to verify the updated Rule 59 no longer flags ICMP/IPv6 infrastructure rules
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, NormalizedRule
from compliance_engine import compliance_engine
import json

class TestRule:
    """Test rule class to simulate NormalizedRule"""
    def __init__(self, **kwargs):
        # Set all the basic fields
        for key, value in kwargs.items():
            setattr(self, key, value)
        
        # Set defaults for missing fields
        if not hasattr(self, 'custom_fields_data'):
            self.custom_fields_data = None
        if not hasattr(self, 'raw_rule'):
            self.raw_rule = None

def test_updated_rule_59():
    """Test the updated Rule 59 against various scenarios"""
    
    with app.app_context():
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        print("🧪 Testing Updated Rule 59 with Zone-Based Filtering")
        print("=" * 60)
        
        # Test Case 1: Your specific ICMP rule (should NOT trigger now)
        print("\n1. Testing ICMP/IPv6 Infrastructure Rule (Your Case)")
        icmp_rule = TestRule(
            action='Allow',
            source_ip='any',
            dest_ip='GTM-IPv6',
            service_port='',
            dest_port='',
            protocol='',
            source_zone='Inbound-Internet',
            dest_zone='Ext-WEB-DMZ',
            application='ping6'
        )
        
        result = compliance_engine.evaluate_rule_against_compliance(icmp_rule, rule59)
        print(f"   Action: {icmp_rule.action}")
        print(f"   Source IP: {icmp_rule.source_ip}")
        print(f"   Dest IP: {icmp_rule.dest_ip}")
        print(f"   Source Zone: {icmp_rule.source_zone}")
        print(f"   Dest Zone: {icmp_rule.dest_zone}")
        print(f"   Application: {icmp_rule.application}")
        print(f"   Result: {'PASS (No Violation)' if result['compliant'] else 'VIOLATION'}")
        print(f"   Expected: PASS (ICMP infrastructure should be allowed)")
        
        if not result['compliant']:
            print(f"   ❌ FAILED: {result['violation_details']}")
        else:
            print("   ✅ SUCCESS: Rule correctly allows ICMP infrastructure")
        
        # Test Case 2: Regular permit rule (should still trigger)
        print("\n2. Testing Regular Permit Rule (Should Still Trigger)")
        regular_rule = TestRule(
            action='permit',
            source_ip='any',
            dest_ip='192.168.1.100',
            service_port='any',
            dest_port='',
            protocol='tcp',
            source_zone='Internal',
            dest_zone='DMZ',
            application='http'
        )
        
        result2 = compliance_engine.evaluate_rule_against_compliance(regular_rule, rule59)
        print(f"   Action: {regular_rule.action}")
        print(f"   Source IP: {regular_rule.source_ip}")
        print(f"   Dest IP: {regular_rule.dest_ip}")
        print(f"   Source Zone: {regular_rule.source_zone}")
        print(f"   Dest Zone: {regular_rule.dest_zone}")
        print(f"   Application: {regular_rule.application}")
        print(f"   Result: {'PASS' if result2['compliant'] else 'VIOLATION (Correct)'}")
        print(f"   Expected: VIOLATION (Regular permit rules should still be flagged)")
        
        if result2['compliant']:
            print("   ❌ FAILED: Rule should have flagged this as violation")
        else:
            print("   ✅ SUCCESS: Rule correctly flags regular permit violations")
        
        # Test Case 3: Rule with different zones (should not trigger due to zone mismatch)
        print("\n3. Testing Rule with Non-Matching Zones")
        zone_rule = TestRule(
            action='Allow',
            source_ip='any',
            dest_ip='server.example.com',
            service_port='any',
            dest_port='',
            protocol='tcp',
            source_zone='Trusted-LAN',
            dest_zone='External-Internet',
            application='https'
        )
        
        result3 = compliance_engine.evaluate_rule_against_compliance(zone_rule, rule59)
        print(f"   Action: {zone_rule.action}")
        print(f"   Source IP: {zone_rule.source_ip}")
        print(f"   Dest IP: {zone_rule.dest_ip}")
        print(f"   Source Zone: {zone_rule.source_zone}")
        print(f"   Dest Zone: {zone_rule.dest_zone}")
        print(f"   Application: {zone_rule.application}")
        print(f"   Result: {'PASS' if result3['compliant'] else 'VIOLATION'}")
        print(f"   Expected: PASS (Different zones should not trigger zone-specific rule)")
        
        if result3['compliant']:
            print("   ✅ SUCCESS: Rule correctly allows different zone combinations")
        else:
            print(f"   ❌ FAILED: {result3['violation_details']}")

if __name__ == "__main__":
    test_updated_rule_59()