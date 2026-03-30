#!/usr/bin/env python3

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from flask import Flask
from sqlalchemy import func

# Create Flask app for database context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewall_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def test_complete_scenario():
    with app.app_context():
        print("=== Complete Upload/Delete Scenario Test ===\n")
        
        # Step 1: Check current state
        raw_total = db.session.query(RawFirewallRule).count()
        normalized_total = db.session.query(NormalizedRule).count()
        normalized_active = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        
        print(f"1. Current state:")
        print(f"   Raw rules: {raw_total}")
        print(f"   Total normalized rules: {normalized_total}")
        print(f"   Active normalized rules: {normalized_active}")
        
        # Show raw rules by file
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        print(f"\n   Raw rules by file:")
        for source_file, count in raw_by_file:
            print(f"     {source_file}: {count} rules")
        
        # Step 2: Simulate "Delete All" (soft delete all normalized rules)
        print(f"\n2. Simulating 'Delete All' normalized rules...")
        deleted_count = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).update({'is_deleted': True})
        db.session.commit()
        
        active_after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Deleted {deleted_count} normalized rules")
        print(f"   Active normalized rules after delete: {active_after_delete}")
        
        # Step 3: Simulate uploading a new file with 8 rules (test_data.csv)
        print(f"\n3. Simulating upload of new file with 8 rules...")
        
        # This is what happens in the current normalization process
        from rule_normalizer import RuleNormalizer
        normalizer = RuleNormalizer()
        
        # Current behavior: normalize_all_rules processes ALL raw rules
        print(f"   Current behavior: normalize_all_rules processes ALL {raw_total} raw rules")
        result = normalizer.normalize_all_rules(source_file='test_data.csv', clear_existing=False)
        
        active_after_upload = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"   Active normalized rules after upload: {active_after_upload}")
        
        # Step 4: Show the problem
        print(f"\n=== THE PROBLEM ===")
        print(f"User expects: 8 rules (only from the uploaded file)")
        print(f"User gets: {active_after_upload} rules (from ALL raw data)")
        print(f"Difference: {active_after_upload - 8} extra rules from old data")
        
        # Step 5: Show which files contributed to the normalized rules
        normalized_by_file = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        print(f"\n   Active normalized rules by file:")
        for source_file, count in normalized_by_file:
            print(f"     {source_file}: {count} rules")

if __name__ == "__main__":
    test_complete_scenario()
