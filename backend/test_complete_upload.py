#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, RawFirewallRule, NormalizedRule
from sqlalchemy import func

def simulate_complete_upload():
    with app.app_context():
        print("=== COMPLETE UPLOAD SIMULATION ===")
        
        # Step 1: Check initial state
        print("\n1. Initial state:")
        raw_total = db.session.query(RawFirewallRule).count()
        normalized_total = db.session.query(NormalizedRule).count()
        active_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        
        print(f"   Raw rules: {raw_total}")
        print(f"   Total normalized rules: {normalized_total}")
        print(f"   Active normalized rules: {active_normalized}")
        
        # Step 2: Delete all normalized rules (simulate "Delete All" button)
        print(f"\n2. Simulating 'Delete All' normalized rules...")
        deleted_count = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).update(
            {'is_deleted': True}, synchronize_session=False
        )
        db.session.commit()
        print(f"   Marked {deleted_count} normalized rules as deleted")
        
        active_after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Active normalized rules after delete: {active_after_delete}")
        
        # Step 3: Simulate uploading a new file with raw rules
        print(f"\n3. Simulating upload of new file...")
        
        # First, let's create some sample raw firewall rules for 'new_upload.csv'
        sample_rules = [
            {
                'source_file': 'new_upload.csv',
                'raw_text': 'access-list OUTSIDE_IN permit tcp 192.168.1.0 255.255.255.0 10.0.0.0 255.0.0.0 eq 80',
                'action': 'permit',
                'source': '192.168.1.0/24',
                'destination': '10.0.0.0/8',
                'dest_port': '80',
                'protocol': 'tcp'
            },
            {
                'source_file': 'new_upload.csv',
                'raw_text': 'access-list OUTSIDE_IN permit tcp 192.168.2.0 255.255.255.0 10.0.0.0 255.0.0.0 eq 443',
                'action': 'permit',
                'source': '192.168.2.0/24',
                'destination': '10.0.0.0/8',
                'dest_port': '443',
                'protocol': 'tcp'
            },
            {
                'source_file': 'new_upload.csv',
                'raw_text': 'access-list OUTSIDE_IN deny ip any any',
                'action': 'deny',
                'source': 'any',
                'destination': 'any',
                'dest_port': 'any',
                'protocol': 'ip'
            }
        ]
        
        # Clear any existing raw rules for this file (simulate the fixed upload process)
        existing_raw = db.session.query(RawFirewallRule).filter(
            RawFirewallRule.source_file == 'new_upload.csv'
        ).count()
        print(f"   Existing raw rules for 'new_upload.csv': {existing_raw}")
        
        if existing_raw > 0:
            db.session.query(RawFirewallRule).filter(
                RawFirewallRule.source_file == 'new_upload.csv'
            ).delete()
            print(f"   Cleared {existing_raw} existing raw rules for 'new_upload.csv'")
        
        # Add new raw rules
        for rule_data in sample_rules:
            raw_rule = RawFirewallRule(**rule_data)
            db.session.add(raw_rule)
        
        db.session.commit()
        print(f"   Added {len(sample_rules)} new raw rules for 'new_upload.csv'")
        
        # Step 4: Trigger normalization (simulate what happens in upload_file)
        print(f"\n4. Triggering normalization for uploaded file...")
        
        from rule_normalizer import RuleNormalizer
        normalizer = RuleNormalizer()
        
        # This is the current behavior in app.py
        result = normalizer.normalize_all_rules(source_file='new_upload.csv', clear_existing=False)
        
        print(f"   Normalization result: {result}")
        
        # Step 5: Check final state
        print(f"\n5. Final state:")
        
        raw_total_after = db.session.query(RawFirewallRule).count()
        normalized_total_after = db.session.query(NormalizedRule).count()
        active_normalized_after = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        
        print(f"   Raw rules: {raw_total_after}")
        print(f"   Total normalized rules: {normalized_total_after}")
        print(f"   Active normalized rules: {active_normalized_after}")
        
        # Show breakdown by source file
        normalized_by_file = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        print(f"\n   Active normalized rules by file:")
        for source_file, count in normalized_by_file:
            print(f"     {source_file}: {count} rules")
        
        # Step 6: Analyze the problem
        print(f"\n=== ANALYSIS ===")
        print(f"Expected behavior:")
        print(f"  - User deletes all rules: 0 active rules")
        print(f"  - User uploads file with 3 rules: 3 active rules")
        print(f"  - Total active rules should be: 3")
        
        print(f"\nActual behavior:")
        print(f"  - After delete all: {active_after_delete} active rules")
        print(f"  - After upload: {active_normalized_after} active rules")
        print(f"  - Difference from expected: {active_normalized_after - 3}")
        
        if active_normalized_after > 3:
            print(f"\n❌ PROBLEM CONFIRMED: Old rules are reappearing!")
            print(f"   The normalization process is recreating rules from old raw data")
        else:
            print(f"\n✅ WORKING CORRECTLY: Only new rules are active")

if __name__ == "__main__":
    simulate_complete_upload()