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

def test_fix():
    with app.app_context():
        print("=== Testing the Fix ===\n")
        
        # Step 1: Count current rules
        initial_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"1. Initial active normalized rules: {initial_normalized}")
        
        # Step 2: Soft delete some rules (simulate user deleting rules)
        rules_to_delete = db.session.query(NormalizedRule).filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.is_deleted == False
        ).limit(5).all()
        
        deleted_count = 0
        for rule in rules_to_delete:
            rule.is_deleted = True
            deleted_count += 1
        
        db.session.commit()
        print(f"2. Soft deleted {deleted_count} rules from observations.csv")
        
        # Step 3: Count active rules after deletion
        after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"3. Active rules after deletion: {after_delete}")
        
        # Step 4: Simulate the old behavior (normalize all rules with clear_existing=True)
        print(f"\n=== Simulating OLD behavior (normalize all with clear_existing=True) ===")
        from rule_normalizer import RuleNormalizer
        normalizer = RuleNormalizer()
        
        # This would bring back deleted rules
        result_old = normalizer.normalize_all_rules(clear_existing=True)
        after_old_normalize = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"4. After OLD normalization (clear all): {after_old_normalize} active rules")
        print(f"   Result: {'DELETED RULES CAME BACK!' if after_old_normalize > after_delete else 'Deleted rules stayed deleted'}")
        
        # Step 5: Delete rules again for new behavior test
        rules_to_delete = db.session.query(NormalizedRule).filter(
            NormalizedRule.source_file == 'observations.csv',
            NormalizedRule.is_deleted == False
        ).limit(5).all()
        
        for rule in rules_to_delete:
            rule.is_deleted = True
        
        db.session.commit()
        after_delete2 = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"5. Deleted 5 more rules. Active rules: {after_delete2}")
        
        # Step 6: Test the NEW behavior (normalize specific file with clear_existing=False)
        print(f"\n=== Testing NEW behavior (normalize specific file with clear_existing=False) ===")
        result_new = normalizer.normalize_all_rules(source_file='test_data.csv', clear_existing=False)
        after_new_normalize = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"6. After NEW normalization (test_data.csv only): {after_new_normalize} active rules")
        print(f"   Result: {'DELETED RULES STAYED DELETED!' if after_new_normalize == after_delete2 else 'Something went wrong'}")
        
        print(f"\n=== Summary ===")
        print(f"The fix ensures that when you upload a new file:")
        print(f"- Only rules from that specific file are normalized")
        print(f"- Existing normalized rules (including deleted ones) are preserved")
        print(f"- Deleted rules do NOT come back")

if __name__ == "__main__":
    test_fix()
