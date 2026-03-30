#!/usr/bin/env python3
"""
Check recent Rule 59 violations to understand why the user thinks the finding is incorrect.
"""

import sys
sys.path.append('/Users/shanjulmittal/FRR/backend')

import json
from datetime import datetime, timedelta
from app import app
from models import ReviewResult, NormalizedRule, ComplianceRule, db

def check_recent_rule59_violations():
    """Check recent Rule 59 violations to understand the issue"""
    with app.app_context():
        # Get Rule 59
        rule59 = ComplianceRule.query.get(59)
        if not rule59:
            print("❌ Rule 59 not found!")
            return
        
        print(f"🔍 Checking recent Rule 59 violations:")
        print(f"Rule: {rule59.rule_name}")
        print(f"Description: {rule59.description}")
        print(f"Severity: {rule59.severity}")
        print()
        
        # Get recent violations (last 7 days)
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        recent_violations = ReviewResult.query.filter(
            ReviewResult.compliance_rule_id == 59,
            ReviewResult.status == 'non_compliant',
            ReviewResult.checked_at >= cutoff_date
        ).order_by(ReviewResult.checked_at.desc()).limit(10).all()
        
        if not recent_violations:
            print("✅ No recent Rule 59 violations found in the last 7 days.")
            print()
            print("🤔 This suggests the user may have encountered the issue:")
            print("   - During a manual review process")
            print("   - With a specific firewall rule that triggered Rule 59")
            print("   - The finding may have been a false positive")
            print()
            print("💡 Rule 59 is designed to detect:")
            print("   - Permit rules with 'any' source IP")
            print("   - Specific destination IP (not 'any')")
            print("   - 'any' or unrestricted service/ports")
            print()
            print("🚨 This is a legitimate security concern!")
            print("   Allowing traffic from anywhere to specific destinations")
            print("   with unrestricted services is generally risky.")
            return
        
        print(f"📊 Found {len(recent_violations)} recent Rule 59 violations:")
        print()
        
        for i, violation in enumerate(recent_violations, 1):
            print(f"Violation #{i}:")
            print(f"  Time: {violation.checked_at}")
            print(f"  Session ID: {violation.review_session_id}")
            print(f"  Normalized Rule ID: {violation.normalized_rule_id}")
            print(f"  Status: {violation.status}")
            print(f"  Severity: {violation.severity}")
            
            if violation.failed_checks:
                try:
                    failed_checks = json.loads(violation.failed_checks)
                    print(f"  Failed Checks: {json.dumps(failed_checks, indent=2)}")
                except:
                    print(f"  Failed Checks: {violation.failed_checks}")
            
            if violation.notes:
                print(f"  Notes: {violation.notes}")
            
            # Get the actual firewall rule details
            norm_rule = NormalizedRule.query.get(violation.normalized_rule_id)
            if norm_rule:
                print(f"  Firewall Rule Details:")
                print(f"    Action: {norm_rule.action}")
                print(f"    Source IP: {norm_rule.source_ip}")
                print(f"    Dest IP: {norm_rule.dest_ip}")
                print(f"    Service Port: {norm_rule.service_port}")
                print(f"    Dest Port: {norm_rule.dest_port}")
                print(f"    Protocol: {norm_rule.protocol}")
                if hasattr(norm_rule, 'raw_rule') and norm_rule.raw_rule:
                    print(f"    Raw Rule: {norm_rule.raw_rule.rule_text[:100]}...")
            
            print()
        
        print("🔍 Analysis:")
        print("=" * 50)
        print("These violations suggest Rule 59 is working as intended.")
        print("The 'incorrect finding' the user mentioned might be:")
        print("1. A false positive - rule triggered on a legitimate business rule")
        print("2. A misunderstanding of what Rule 59 is supposed to detect")
        print("3. Need for rule tuning - maybe the rule is too broad")
        print()
        print("💡 Rule 59 detects: 'Permit + Any Source + Specific Dest + Any Service'")
        print("   This is generally a security risk and should be reviewed carefully.")

if __name__ == '__main__':
    check_recent_rule59_violations()