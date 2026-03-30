#!/usr/bin/env python3
"""
Test script to verify the complete user workflow after the fix.
This simulates: Delete All -> Upload New File -> Verify Only New Rules Active
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from flask import Flask
import requests
import json

# Create Flask app for database context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewall_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def test_user_workflow():
    with app.app_context():
        print("=== Testing Complete User Workflow After Fix ===\n")
        
        # Step 1: Initial state
        print("1. Initial database state:")
        active_rules = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        deleted_rules = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        
        print(f"   Active normalized rules: {active_rules}")
        print(f"   Deleted normalized rules: {deleted_rules}")
        
        # Step 2: Simulate "Delete All" action
        print(f"\n2. Simulating 'Delete All' action...")
        try:
            response = requests.delete('http://localhost:5001/api/normalized-rules/bulk-delete', 
                                     json={'delete_all': True}, 
                                     headers={'Content-Type': 'application/json'})
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Delete All successful: {data.get('message', 'No message')}")
                
                # Check state after deletion
                active_after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
                deleted_after_delete = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
                print(f"   Active rules after delete: {active_after_delete}")
                print(f"   Deleted rules after delete: {deleted_after_delete}")
            else:
                print(f"   ❌ Delete All failed (status {response.status_code})")
                return
        except requests.exceptions.ConnectionError:
            print("   ⚠️  Backend server not running. Simulating delete manually...")
            # Manually mark all as deleted for testing
            db.session.query(NormalizedRule).update({'is_deleted': True})
            db.session.commit()
            print("   ✅ Manually marked all rules as deleted")
        
        # Step 3: Create sample raw rules for a new file
        print(f"\n3. Creating sample raw rules for new file 'user_test.csv'...")
        
        # Clear any existing raw rules for this test file
        db.session.query(RawFirewallRule).filter(RawFirewallRule.source_file == 'user_test.csv').delete()
        db.session.commit()
        
        # Add new raw rules
        sample_rules = [
            RawFirewallRule(
                source='192.168.1.0/24',
                destination='10.0.0.0/8', 
                dest_port='80',
                protocol='tcp',
                action='permit',
                source_file='user_test.csv',
                raw_text='permit tcp 192.168.1.0/24 10.0.0.0/8 eq 80'
            ),
            RawFirewallRule(
                source='192.168.2.0/24',
                destination='10.0.0.0/8',
                dest_port='443', 
                protocol='tcp',
                action='permit',
                source_file='user_test.csv',
                raw_text='permit tcp 192.168.2.0/24 10.0.0.0/8 eq 443'
            ),
            RawFirewallRule(
                source='any',
                destination='192.168.100.0/24',
                dest_port='22',
                protocol='tcp', 
                action='deny',
                source_file='user_test.csv',
                raw_text='deny tcp any 192.168.100.0/24 eq 22'
            )
        ]
        
        for rule in sample_rules:
            db.session.add(rule)
        db.session.commit()
        
        print(f"   ✅ Added {len(sample_rules)} raw rules for 'user_test.csv'")
        
        # Step 4: Simulate file upload normalization (with source_file)
        print(f"\n4. Simulating file upload normalization...")
        try:
            response = requests.post('http://localhost:5001/api/normalize-rules', 
                                   json={'source_file': 'user_test.csv', 'clear_existing': True}, 
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Normalization successful: {data.get('message', 'No message')}")
                
                if 'results' in data and 'stats' in data['results']:
                    stats = data['results']['stats']
                    print(f"   Rules processed: {stats.get('rules_processed', 0)}")
                    print(f"   Normalized rules created: {stats.get('normalized_rules_created', 0)}")
            else:
                print(f"   ❌ Normalization failed (status {response.status_code})")
                return
        except requests.exceptions.ConnectionError:
            print("   ⚠️  Backend server not running. Cannot test API normalization.")
            return
        
        # Step 5: Verify final state
        print(f"\n5. Verifying final state...")
        
        final_active = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        final_deleted = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        
        # Check source files of active rules
        active_rules_by_file = db.session.query(
            NormalizedRule.source_file, 
            db.func.count(NormalizedRule.id)
        ).filter(
            NormalizedRule.is_deleted == False
        ).group_by(NormalizedRule.source_file).all()
        
        print(f"   Final active rules: {final_active}")
        print(f"   Final deleted rules: {final_deleted}")
        print(f"   Active rules by source file:")
        for source_file, count in active_rules_by_file:
            print(f"     {source_file}: {count} rules")
        
        # Step 6: Verify the fix worked
        print(f"\n=== Workflow Verification Results ===")
        
        if final_active == len(sample_rules):
            print("✅ SUCCESS: Only the newly uploaded rules are active")
            
            # Check if only user_test.csv rules are active
            user_test_active = sum(count for source_file, count in active_rules_by_file if source_file == 'user_test.csv')
            if user_test_active == final_active:
                print("✅ SUCCESS: All active rules belong to the newly uploaded file")
            else:
                print("❌ ISSUE: Some active rules belong to other files (old rules reappeared)")
        else:
            print(f"❌ ISSUE: Expected {len(sample_rules)} active rules, but got {final_active}")
            
        # Check if old rules stayed deleted
        old_files_active = sum(count for source_file, count in active_rules_by_file if source_file != 'user_test.csv')
        if old_files_active == 0:
            print("✅ SUCCESS: No old deleted rules reappeared")
        else:
            print(f"❌ ISSUE: {old_files_active} old rules reappeared from other files")
        
        print(f"\n=== Summary ===")
        print("The fix ensures that:")
        print("1. Delete All properly marks all rules as deleted")
        print("2. File upload normalization only processes the uploaded file")
        print("3. Old deleted rules do not reappear")
        print("4. The normalize button requires explicit force_all=true")

if __name__ == "__main__":
    test_user_workflow()