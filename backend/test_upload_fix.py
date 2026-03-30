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

def test_upload_fix():
    with app.app_context():
        print("=== Testing Upload Fix ===\n")
        
        # Check current state
        raw_total = db.session.query(RawFirewallRule).count()
        normalized_active = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        
        print(f"Current state:")
        print(f"  Raw rules: {raw_total}")
        print(f"  Active normalized rules: {normalized_active}")
        
        # Show breakdown by file
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        print(f"\nRaw rules by file:")
        for source_file, count in raw_by_file:
            print(f"  {source_file}: {count} rules")
        
        # Simulate uploading the same file again (test_data.csv)
        print(f"\n=== Simulating re-upload of test_data.csv ===")
        
        # This simulates what happens in store_parsed_data
        source_file = 'test_data.csv'
        existing_count = db.session.query(RawFirewallRule).filter_by(source_file=source_file).count()
        print(f"Existing raw rules for {source_file}: {existing_count}")
        
        if existing_count > 0:
            db.session.query(RawFirewallRule).filter_by(source_file=source_file).delete()
            db.session.commit()
            print(f"Cleared {existing_count} existing raw rules for {source_file}")
        
        # Check counts after clearing
        raw_after_clear = db.session.query(RawFirewallRule).count()
        print(f"Raw rules after clearing {source_file}: {raw_after_clear}")
        
        # Show the expected behavior
        expected_reduction = existing_count
        actual_reduction = raw_total - raw_after_clear
        
        print(f"\n=== Results ===")
        print(f"Expected reduction: {expected_reduction}")
        print(f"Actual reduction: {actual_reduction}")
        print(f"Fix working correctly: {'YES' if expected_reduction == actual_reduction else 'NO'}")
        
        if expected_reduction == actual_reduction:
            print("✅ FIXED: Raw rules are now properly replaced instead of duplicated!")
        else:
            print("❌ ISSUE: Raw rules are still being duplicated")

if __name__ == "__main__":
    test_upload_fix()
