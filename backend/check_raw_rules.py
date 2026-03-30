#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, RawFirewallRule, NormalizedRule
from sqlalchemy import func

def check_raw_rules():
    with app.app_context():
        print("=== RAW FIREWALL RULES ANALYSIS ===")
        
        # Get total count
        total_raw = db.session.query(RawFirewallRule).count()
        print(f"Total raw firewall rules: {total_raw}")
        
        # Get breakdown by source file
        raw_by_file = db.session.query(
            RawFirewallRule.source_file,
            func.count(RawFirewallRule.id).label('count')
        ).group_by(RawFirewallRule.source_file).all()
        
        print(f"\nRaw rules by source file:")
        for source_file, count in raw_by_file:
            print(f"  {source_file}: {count} rules")
        
        # Check if test_data.csv exists
        test_data_count = db.session.query(RawFirewallRule).filter(
            RawFirewallRule.source_file == 'test_data.csv'
        ).count()
        print(f"\nRaw rules for 'test_data.csv': {test_data_count}")
        
        # Show a few sample raw rules
        sample_rules = db.session.query(RawFirewallRule).limit(3).all()
        print(f"\nSample raw rules:")
        for rule in sample_rules:
            print(f"  ID: {rule.id}, Source: {rule.source_file}, Action: {rule.action}")

if __name__ == "__main__":
    check_raw_rules()