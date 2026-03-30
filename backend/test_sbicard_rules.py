
import json
import logging
from app import app
from compliance_engine import ComplianceEngine
from models import ComplianceRule

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockRule:
    def __init__(self, **kwargs):
        self.source_ip = kwargs.get('source_ip', '')
        self.dest_ip = kwargs.get('dest_ip', '')
        self.service_port = kwargs.get('service_port', '')
        self.dest_port = kwargs.get('dest_port', '')
        self.service_name = kwargs.get('service_name', '')
        self.protocol = kwargs.get('protocol', '')
        self.application = kwargs.get('application', '')
        self.action = kwargs.get('action', 'permit')
        self.rule_name = kwargs.get('rule_name', 'Test Rule')
        self.source_zone = kwargs.get('source_zone', '')
        self.dest_zone = kwargs.get('dest_zone', '')
        self.source_vlan_name = kwargs.get('source_vlan_name', '')
        self.hit_count = kwargs.get('hit_count', 100)
        self.raw_rule = kwargs.get('raw_rule', None)
        self.source_hostname = kwargs.get('source_hostname', '')
        self.dest_hostname = kwargs.get('dest_hostname', '')
        
        # Custom fields
        self.custom_fields_data = json.dumps(kwargs.get('custom_fields', {}))

import compliance_engine as ce_module
from unittest.mock import patch

def mock_categories(ip_field, hostname_field):
    if '1.1.1.1' in ip_field: return ['A']
    if '2.2.2.2' in ip_field: return ['C']
    return []

def test_rule(engine, rule_id, mock_rule, expected_compliant):
    with app.app_context():
        compliance_rule = ComplianceRule.query.get(rule_id)
        if not compliance_rule:
            print(f"Rule {rule_id} not found!")
            return False

        result = engine.evaluate_rule_against_compliance(mock_rule, compliance_rule)
        is_compliant = result['compliant']
        
        status = "PASS" if is_compliant == expected_compliant else "FAIL"
        print(f"Rule {rule_id} ({compliance_rule.rule_name}): {status}")
        if status == "FAIL":
            print(f"  Expected: {expected_compliant}, Got: {is_compliant}")
            print(f"  Details: {result}")
            print(f"  Mock Data: {mock_rule.__dict__}")
        return status == "PASS"

def run_tests():
    engine = ComplianceEngine()
    
    # Mock CMDB categories for Rule 64
    ce_module._categories_for_fields = lambda ips, hosts: ['A'] if '1.1.1.1' in ips else (['C'] if '2.2.2.2' in ips else [])

    print("Starting SBICARD Profile Tests...")
    
    # Rule 39: Permit + Any Source + Specific Dest/Service
    # Condition: source=any AND dest!=any AND service!=any AND zones match
    # Expect: Non-Compliant if matches
    r39_fail = MockRule(source_ip='any', dest_ip='10.10.10.10', service_port='80', 
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 39, r39_fail, False) # Should be Non-Compliant (True violation)

    r39_pass = MockRule(source_ip='1.1.1.1', dest_ip='10.10.10.10', service_port='80', 
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 39, r39_pass, True)

    # Rule 40: Permit + Specific Source + Any Dest
    # Condition: source!=any AND dest=any AND service!=any AND zones match
    r40_fail = MockRule(source_ip='1.1.1.1', dest_ip='any', service_port='80',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 40, r40_fail, False)

    # Rule 44: Excessive Services (>=100)
    r44_fail = MockRule(custom_fields={'service_count': 105})
    test_rule(engine, 44, r44_fail, False)
    
    r44_pass = MockRule(custom_fields={'service_count': 10})
    test_rule(engine, 44, r44_pass, True)

    # Rule 45: Disabled Rules
    r45_fail = MockRule(rule_name="This rule is DISABLED temporarily")
    test_rule(engine, 45, r45_fail, False)

    r45_pass = MockRule(rule_name="Active Rule")
    test_rule(engine, 45, r45_pass, True)

    # Rule 46: Zero Hit Count
    r46_fail = MockRule(hit_count=0)
    test_rule(engine, 46, r46_fail, False)

    r46_pass = MockRule(hit_count=500)
    test_rule(engine, 46, r46_pass, True)

    r46_exempt = MockRule(hit_count=None)
    test_rule(engine, 46, r46_exempt, True)

    # Rule 47: HTTP/80 or non-443 open from internet
    # Condition: source=any AND (service=80 OR service!=443) AND zones match
    r47_fail = MockRule(source_ip='any', service_port='80',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 47, r47_fail, False)

    r47_pass = MockRule(source_ip='any', service_port='443', dest_port='443',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 47, r47_pass, True)

    # Rule 49: DB ports from User/WiFi VLANs
    # Condition: vlan contains user/wifi AND service/dest port in [1521, 1433...]
    r49_fail = MockRule(source_vlan_name='corp-user-vlan', service_port='1433')
    test_rule(engine, 49, r49_fail, False)

    r49_pass = MockRule(source_vlan_name='server-vlan', service_port='1433')
    test_rule(engine, 49, r49_pass, True)

    # Rule 50: RDP/SSH only from Citrix
    # Condition: source != citrix AND (service=22/3389) AND zones match
    # This was the broken one we fixed.
    r50_fail = MockRule(source_ip='1.2.3.4', service_port='22',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 50, r50_fail, False)

    r50_pass_citrix = MockRule(source_ip='citrix-gateway', service_port='22',
                              source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 50, r50_pass_citrix, True)
    
    r50_pass_other_service = MockRule(source_ip='1.2.3.4', service_port='443',
                                     source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 50, r50_pass_other_service, True)

    # Rule 55: High risk ports
    r55_fail = MockRule(dest_port='445')
    test_rule(engine, 55, r55_fail, False)

    # Rule 56: Restricted services
    r56_fail = MockRule(service_name='FTP')
    test_rule(engine, 56, r56_fail, False)

    # Rule 57: Unsecured LDAP
    r57_fail = MockRule(service_port='389', action='permit')
    test_rule(engine, 57, r57_fail, False)

    # Rule 58: No Any-Any-Any
    r58_fail = MockRule(source_ip='any', dest_ip='any', service_port='any',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 58, r58_fail, False)

    # Rule 59: Permit + Any Source + Specific Dest + Any Service
    r59_fail = MockRule(source_ip='any', dest_ip='1.2.3.4', service_port='any',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 59, r59_fail, False)

    # Rule 60: Permit + Specific Source + Any Dest + Any Service
    r60_fail = MockRule(source_ip='1.2.3.4', dest_ip='any', service_port='any',
                       source_zone='Inbound-Internet', dest_zone='Ext-WEB-DMZ')
    test_rule(engine, 60, r60_fail, False)

    # Rule 63: Business Documentation
    r63_pass = MockRule(rule_name="CHG12345 - New Server")
    test_rule(engine, 63, r63_pass, True)

    r63_fail = MockRule(rule_name="Just a test rule")
    test_rule(engine, 63, r63_fail, False)

    # Rule 64: PCIDSS zone violation (Composite - custom operator)
    # Mock CMDB categories: src=A, dst=C (violation: allow A->C)
    # But action=permit. So it's a violation?
    # Operator logic: if action=permit/allow and ( (src=C and dst!=C) or (src!=C and dst=C) ) -> Violation
    # Here src=A(!=C), dst=C. Violation!
    # So expected_compliant = False.
    r64_fail = MockRule(source_ip='1.1.1.1', dest_ip='2.2.2.2', action='permit')
    with patch.object(engine, '_get_categories_for_fields', side_effect=mock_categories):
        test_rule(engine, 64, r64_fail, False) # Expected: False (Violation)
    
    # Pass case: src=C, dst=C (intra-C allowed?) or src=A, dst=B (non-C allowed?)
    # If src=C, dst=C -> No violation?
    # Logic: if src in C_cats and dst in C_cats -> OK?
    # Logic: violation if (src_has_C and not dst_has_C) OR (not src_has_C and dst_has_C)
    # If both C -> No violation.
    # We need to mock returning C for both.
    def mock_categories_pass(ip, host):
        return ['C']
        
    r64_pass = MockRule(source_ip='2.2.2.2', dest_ip='2.2.2.2', action='permit')
    with patch.object(engine, '_get_categories_for_fields', side_effect=mock_categories_pass):
        test_rule(engine, 64, r64_pass, True)

if __name__ == "__main__":
    run_tests()
