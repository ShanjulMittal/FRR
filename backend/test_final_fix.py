#!/usr/bin/env python3

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from flask import Flask

# Create Flask app for database context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewall_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def test_final_fix():
    with app.app_context():
        print("=== Testing the Final Fix ===\n")
        
        # Step 1: Reset - normalize all rules first
        from rule_normalizer import RuleNormalizer
        normalizer = RuleNormalizer()
        normalizer.normalize_all_rules(clear_existing=True)
        
        initial_count = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"1. Initial active normalized rules: {initial_count}")
        
        # Step 2: Delete some rules from observations.csv
        rules_to_delete = db.session.query(NormalizedRule).filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.is_deleted == False
        ).limit(10).all()
        
        deleted_count = len(rules_to_delete)
        for rule in rules_to_delete:
            rule.is_deleted = True
        
        db.session.commit()
        after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"2. Deleted {deleted_count} rules from observations.csv")
        print(f"   Active rules after deletion: {after_delete}")
        
        # Step 3: Test uploading a new file (simulate upload normalization)
        print(f"\n3. Simulating upload of test_data.csv (NEW behavior)...")
        result = normalizer.normalize_all_rules(source_file='test_data.csv', clear_existing=False)
        
        after_upload = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Active rules after upload normalization: {after_upload}")
        
        # Check if deleted rules stayed deleted
        deleted_rules_still_deleted = db.session.query(NormalizedRule).filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.is_deleted == True
        ).count()
        
        print(f"   Deleted rules from observations.csv still deleted: {deleted_rules_still_deleted}")
        
        # Step 4: Verify the fix worked
        expected_count = after_delete  # Should be the same as after deletion
        success = after_upload == expected_count
        
        print(f"\n=== Results ===")
        print(f"Expected active rules: {expected_count}")
        print(f"Actual active rules: {after_upload}")
        print(f"Fix successful: {'YES' if success else 'NO'}")
        
        if success:
            print("✅ FIXED: Deleted rules no longer reappear after upload!")
        else:
            print("❌ ISSUE: Deleted rules still reappearing or other problem")
            
        # Show breakdown by file
        print(f"\n=== Active Rules by Source File ===")
        from sqlalchemy import func
        active_by_file = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        for source_file, count in active_by_file:
            print(f"  {source_file}: {count} active rules")

if __name__ == "__main__":
    test_final_fix()
