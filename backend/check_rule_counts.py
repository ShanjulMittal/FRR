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

def check_counts():
    with app.app_context():
        print("=== Current Rule Counts ===\n")
        
        # Raw rules count
        raw_total = db.session.query(RawFirewallRule).count()
        print(f"Total Raw Firewall Rules: {raw_total}")
        
        # Raw rules by source file
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        print("\nRaw Rules by Source File:")
        for source_file, count in raw_by_file:
            print(f"  {source_file}: {count} rules")
        
        # Normalized rules count
        normalized_total = db.session.query(NormalizedRule).count()
        normalized_active = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        normalized_deleted = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        
        print(f"\nTotal Normalized Rules: {normalized_total}")
        print(f"Active Normalized Rules: {normalized_active}")
        print(f"Deleted Normalized Rules: {normalized_deleted}")
        
        # Normalized rules by source file
        normalized_by_file = db.session.query(
            NormalizedRule.source_file,
            func.count(NormalizedRule.id).label('count')
        ).filter(NormalizedRule.is_deleted == False).group_by(NormalizedRule.source_file).all()
        
        print("\nActive Normalized Rules by Source File:")
        for source_file, count in normalized_by_file:
            print(f"  {source_file}: {count} rules")

if __name__ == "__main__":
    check_counts()
