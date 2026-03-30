#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, RawFirewallRule, NormalizedRule
from sqlalchemy import func

def debug_user_scenario():
    with app.app_context():
        print("=== DEBUGGING USER SCENARIO ===")
        
        # Step 1: Current state
        print("\n1. Current database state:")
        raw_total = db.session.query(RawFirewallRule).count()
        normalized_total = db.session.query(NormalizedRule).count()
        active_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        deleted_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        
        print(f"   Raw rules: {raw_total}")
        print(f"   Total normalized rules: {normalized_total}")
        print(f"   Active normalized rules: {active_normalized}")
        print(f"   Deleted normalized rules: {deleted_normalized}")
        
        # Show breakdown by source file
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        print(f"\n   Raw rules by source file:")
        for source_file, count in raw_by_file:
            print(f"     {source_file}: {count} rules")
        
        normalized_by_file = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        print(f"\n   Active normalized rules by source file:")
        for source_file, count in normalized_by_file:
            print(f"     {source_file}: {count} rules")
        
        # Step 2: Simulate user's "Delete All" action
        print(f"\n2. Simulating user's 'Delete All' action...")
        
        # Mark all active normalized rules as deleted
        deleted_count = db.session.query(NormalizedRule).filter(
            NormalizedRule.is_deleted == False
        ).update({'is_deleted': True}, synchronize_session=False)
        db.session.commit()
        
        print(f"   Marked {deleted_count} normalized rules as deleted")
        
        active_after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Active normalized rules after delete: {active_after_delete}")
        
        # Step 3: Check what happens if we call normalize_all_rules WITHOUT source_file
        print(f"\n3. Testing normalization WITHOUT source_file (potential bug)...")
        
        from rule_normalizer import RuleNormalizer
        normalizer = RuleNormalizer()
        
        # This might be what's happening if the upload process has a bug
        result = normalizer.normalize_all_rules(clear_existing=False)
        
        print(f"   Normalization result: {result}")
        
        active_after_normalize = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Active normalized rules after normalization: {active_after_normalize}")
        
        # Show which files contributed
        normalized_by_file_after = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        print(f"\n   Active normalized rules by source file after normalization:")
        for source_file, count in normalized_by_file_after:
            print(f"     {source_file}: {count} rules")
        
        # Step 4: Analysis
        print(f"\n=== ANALYSIS ===")
        print(f"This test shows what happens if normalize_all_rules is called without source_file")
        print(f"Expected: Only new rules should be normalized")
        print(f"Actual: {active_after_normalize} rules are now active")
        
        if active_after_normalize > 50:  # Assuming user uploaded ~40 rules
            print(f"❌ PROBLEM IDENTIFIED: normalize_all_rules without source_file processes ALL raw rules")
            print(f"   This would cause old deleted rules to reappear")
        else:
            print(f"✅ No issue found with this scenario")

if __name__ == "__main__":
    debug_user_scenario()