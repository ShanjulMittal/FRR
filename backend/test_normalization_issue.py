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

def analyze_normalization_issue():
    with app.app_context():
        print("=== Analyzing Normalization Issue ===\n")
        
        # Count raw rules
        raw_count = db.session.query(RawFirewallRule).count()
        print(f"Total Raw Firewall Rules: {raw_count}")
        
        # Count normalized rules (all)
        all_normalized = db.session.query(NormalizedRule).count()
        print(f"Total Normalized Rules (including deleted): {all_normalized}")
        
        # Count active normalized rules
        active_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        print(f"Active Normalized Rules: {active_normalized}")
        
        # Count deleted normalized rules
        deleted_normalized = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        print(f"Deleted Normalized Rules: {deleted_normalized}")
        
        print(f"\n=== The Problem ===")
        print(f"When normalization runs, it:")
        print(f"1. Deletes ALL {all_normalized} normalized rules (including soft-deleted ones)")
        print(f"2. Recreates rules from ALL {raw_count} raw rules")
        print(f"3. This brings back the {deleted_normalized} rules you thought you deleted!")
        
        # Show breakdown by source file
        print(f"\n=== Raw Rules by Source File ===")
        from sqlalchemy import func
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        for source_file, count in raw_by_file:
            print(f"  {source_file}: {count} raw rules")

if __name__ == "__main__":
    analyze_normalization_issue()
