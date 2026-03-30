
import sys
import os
import logging
from flask import Flask

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from compliance_engine import ComplianceEngine
from models import NormalizedRule, ComplianceRule, db

# Mock Flask app for context if needed, though ComplianceEngine might not strictly need it for unit test
app = Flask(__name__)

def test_application_any_inclusion():
    print("Testing application field inclusion in service/port checks...")
    
    engine = ComplianceEngine()
    
    # Case 1: Service is specific, but Application is ANY
    # This represents a firewall rule like "permit tcp any host 1.2.3.4 eq 80 application any"
    rule_with_app_any = NormalizedRule(
        source_ip="10.0.0.1",
        dest_ip="20.0.0.1",
        service_port="80",
        dest_port="80",
        service_name="http",
        application="ANY",  # <--- This is the key
        action="permit"
    )
    
    # Compliance Rule: Check if service_port contains "ANY"
    # This mimics a rule checking for open/any services
    compliance_rule = ComplianceRule(
        rule_name="Check Service ANY",
        description="Fail if service is ANY",
        field_to_check="service_port",  # The engine aggregates into this
        operator="contains", # or in_list, regex_match etc.
        value="ANY",
        severity="high"
    )
    
    # We expect this to match "ANY" because application="ANY" is aggregated into service_port evaluation
    # Since violation_mode is True by default (match = violation), we expect compliant=False if it matches
    
    # Force violation_mode=True for test (default is True)
    engine.violation_mode = True
    
    result = engine.evaluate_rule_against_compliance(rule_with_app_any, compliance_rule)
    
    print(f"Result for Application='ANY': {result}")
    
    if result['compliant'] is False and "ANY" in str(result.get('field_value', '')):
        print("SUCCESS: Application 'ANY' was detected in service_port check.")
    else:
        print("FAILURE: Application 'ANY' was NOT detected.")
        print(f"Field Value evaluated: {result.get('field_value')}")

    # Case 2: Service is specific, Application is specific
    rule_specific = NormalizedRule(
        service_port="80",
        application="web-browsing"
    )
    
    result_specific = engine.evaluate_rule_against_compliance(rule_specific, compliance_rule)
    print(f"Result for Specific: {result_specific}")
    
    if result_specific['compliant'] is True:
        print("SUCCESS: Specific application correctly passed.")
    else:
        print("FAILURE: Specific application falsely flagged.")

    # Case 3: Composite Rule (Permutations)
    print("\nTesting Composite Rule (Permutations)...")
    # Rule: Violation if (Source ANY) AND (Service/App ANY)
    composite_rule = ComplianceRule(
        rule_name="Composite Permutation Check",
        description="Violation if Source ANY and Service ANY",
        operator="composite",
        value='{"logic": "AND", "conditions": [{"field": "source_ip", "operator": "equals", "value": "any"}, {"field": "service_port", "operator": "contains", "value": "any"}]}',
        severity="high"
    )

    # Test Rule: Source ANY, Service Specific, App ANY -> Should Violate
    rule_composite = NormalizedRule(
        source_ip="any",
        service_port="80",
        application="ANY"
    )
    
    # Evaluate
    res_comp = engine.evaluate_rule_against_compliance(rule_composite, composite_rule)
    print(f"Result for Composite: {res_comp}")
    
    if res_comp['compliant'] is False:
         print("SUCCESS: Composite rule correctly detected violation due to Application='ANY'.")
    else:
         print("FAILURE: Composite rule missed the violation.")

if __name__ == "__main__":
    test_application_any_inclusion()
