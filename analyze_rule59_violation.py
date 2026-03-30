#!/usr/bin/env python3
"""
Analyze the specific Rule 59 violation to understand why it's incorrect.
"""

import sys
sys.path.append('/Users/shanjulmittal/FRR/backend')

import json
from app import app
from models import ReviewResult, NormalizedRule, ComplianceRule, db

def analyze_specific_rule59_violation():
    """Analyze the specific violation that the user thinks is incorrect"""
    with app.app_context():
        # Get the specific violation
        violation = ReviewResult.query.filter(
            ReviewResult.compliance_rule_id == 59,
            ReviewResult.status == 'non_compliant',
            ReviewResult.normalized_rule_id == 2827
        ).first()
        
        if not violation:
            print("❌ Rule 59 violation for normalized rule 2827 not found!")
            return
        
        print("🔍 Analyzing Specific Rule 59 Violation:")
        print("=" * 60)
        print(f"Violation ID: {violation.id}")
        print(f"Session ID: {violation.review_session_id}")
        print(f"Normalized Rule ID: {violation.normalized_rule_id}")
        print(f"Status: {violation.status}")
        print(f"Severity: {violation.severity}")
        print(f"Checked At: {violation.checked_at}")
        print()
        
        # Get the actual firewall rule
        norm_rule = NormalizedRule.query.get(violation.normalized_rule_id)
        if not norm_rule:
            print("❌ Normalized rule not found!")
            return
        
        print("📋 Firewall Rule Details:")
        print("=" * 60)
        print(f"Action: {norm_rule.action}")
        print(f"Source IP: {norm_rule.source_ip}")
        print(f"Dest IP: {norm_rule.dest_ip}")
        print(f"Service Port: '{norm_rule.service_port}'")
        print(f"Dest Port: '{norm_rule.dest_port}'")
        print(f"Protocol: '{norm_rule.protocol}'")
        print(f"Service Name: '{norm_rule.service_name if hasattr(norm_rule, 'service_name') else 'N/A'}'")
        print()
        
        if norm_rule.raw_rule:
            print(f"Raw Rule Text: {norm_rule.raw_rule.rule_text}")
            print()
        
        # Get Rule 59 definition
        rule59 = ComplianceRule.query.get(59)
        print("📋 Rule 59 Definition:")
        print("=" * 60)
        print(f"Rule Name: {rule59.rule_name}")
        print(f"Description: {rule59.description}")
        print(f"Severity: {rule59.severity}")
        print()
        
        # Analyze why this rule triggered Rule 59
        print("🔍 Analysis: Why This Rule Triggered Rule 59")
        print("=" * 60)
        
        # Check each condition
        conditions_met = []
        
        # Condition 1: Action = permit
        if norm_rule.action and norm_rule.action.lower() in ['permit', 'allow']:
            conditions_met.append("✅ Action = permit/allow")
        else:
            conditions_met.append("❌ Action ≠ permit/allow")
        
        # Condition 2: Source IP = any
        if norm_rule.source_ip and norm_rule.source_ip.lower() == 'any':
            conditions_met.append("✅ Source IP = any")
        else:
            conditions_met.append("❌ Source IP ≠ any")
        
        # Condition 3: Dest IP ≠ any and not empty
        if norm_rule.dest_ip and norm_rule.dest_ip.lower() != 'any':
            conditions_met.append("✅ Dest IP ≠ any")
        else:
            conditions_met.append("❌ Dest IP = any")
        
        # Condition 4: Service/Port = any or empty or full range
        service_any = False
        if (not norm_rule.service_port or norm_rule.service_port.strip() == '' or 
            norm_rule.service_port.lower() == 'any'):
            service_any = True
            conditions_met.append("✅ Service Port = any/empty")
        
        if (not norm_rule.dest_port or norm_rule.dest_port.strip() == '' or 
            norm_rule.dest_port.lower() == 'any'):
            service_any = True
            conditions_met.append("✅ Dest Port = any/empty")
        
        if not service_any:
            conditions_met.append("❌ Service/Port ≠ any/empty")
        
        print("Conditions Met:")
        for condition in conditions_met:
            print(f"  {condition}")
        print()
        
        # Determine if this is a legitimate violation
        legitimate_violation = True
        if len([c for c in conditions_met if c.startswith("✅")]) >= 4:  # All key conditions met
            print("🚨 LEGITIMATE VIOLATION DETECTED:")
            print("   This rule allows traffic from ANY source to a specific destination")
            print("   with unrestricted services. This is a legitimate security concern!")
            print()
            print("💡 Recommendations:")
            print("   1. Review if this rule is actually necessary for business")
            print("   2. Consider restricting source IP ranges if possible")
            print("   3. Consider restricting service ports if possible")
            print("   4. Document the business justification for this rule")
        else:
            print("⚠️  POTENTIAL FALSE POSITIVE:")
            print("   Rule 59 triggered but not all conditions are clearly met")
            print("   This might be an edge case or logic issue")
            print()
            print("🔍 Investigate:")
            print("   1. Check if destination 'GTM-IPv6' should be considered 'specific'")
            print("   2. Verify service/port evaluation logic")
            print("   3. Check for edge cases in the rule logic")
        
        print()
        print("📊 Final Assessment:")
        print("=" * 60)
        print("Rule 59 is working as designed, but the user may have")
        print("encountered this specific rule and believes it's legitimate")
        print("business traffic that shouldn't be flagged as a violation.")
        print()
        print("🎯 Next Steps:")
        print("1. Review the specific business case for this firewall rule")
        print("2. Consider if Rule 59 needs tuning for IPv6 destinations")
        print("3. Consider adding exceptions for specific destination types")
        print("4. Document why this rule is acceptable if it's truly needed")

if __name__ == '__main__':
    analyze_specific_rule59_violation()