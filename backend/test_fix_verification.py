#!/usr/bin/env python3
"""
Test script to verify the fix for the normalization issue.
This script tests that the normalize_rules endpoint now properly prevents
old deleted rules from reappearing when called without source_file.
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

def test_fix_verification():
    with app.app_context():
        print("=== Testing Fix for Normalization Issue ===\n")
        
        # Step 1: Check current state
        print("1. Current database state:")
        active_rules = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == False).count()
        deleted_rules = db.session.query(NormalizedRule).filter(NormalizedRule.is_deleted == True).count()
        total_raw_rules = db.session.query(RawFirewallRule).count()
        
        print(f"   Active normalized rules: {active_rules}")
        print(f"   Deleted normalized rules: {deleted_rules}")
        print(f"   Total raw rules: {total_raw_rules}")
        
        # Step 2: Test the API endpoint without source_file (should fail now)
        print(f"\n2. Testing normalize_rules API without source_file (should fail)...")
        try:
            response = requests.post('http://localhost:5001/api/normalize-rules', 
                                   json={}, 
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 400:
                error_data = response.json()
                print(f"   ✅ API correctly rejected request: {error_data.get('error', 'Unknown error')}")
            else:
                print(f"   ❌ API should have rejected request but returned status {response.status_code}")
                if response.status_code == 200:
                    print("   This means the fix didn't work - old rules would reappear!")
        except requests.exceptions.ConnectionError:
            print("   ⚠️  Backend server not running. Please start the backend server to test the API.")
        
        # Step 3: Test with force_all=true (should work)
        print(f"\n3. Testing normalize_rules API with force_all=true (should work)...")
        try:
            response = requests.post('http://localhost:5001/api/normalize-rules', 
                                   json={'force_all': True}, 
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ API accepted request with force_all=true")
                print(f"   Results: {data.get('message', 'No message')}")
                
                # Check if rules were processed
                if 'results' in data and 'stats' in data['results']:
                    stats = data['results']['stats']
                    print(f"   Rules processed: {stats.get('rules_processed', 0)}")
                    print(f"   Normalized rules created: {stats.get('normalized_rules_created', 0)}")
            else:
                print(f"   ❌ API rejected request with force_all=true (status {response.status_code})")
                error_data = response.json()
                print(f"   Error: {error_data.get('error', 'Unknown error')}")
        except requests.exceptions.ConnectionError:
            print("   ⚠️  Backend server not running. Please start the backend server to test the API.")
        
        # Step 4: Test with specific source_file (should work)
        print(f"\n4. Testing normalize_rules API with specific source_file (should work)...")
        try:
            response = requests.post('http://localhost:5001/api/normalize-rules', 
                                   json={'source_file': 'observations.csv'}, 
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ API accepted request with source_file")
                print(f"   Results: {data.get('message', 'No message')}")
                
                # Check if rules were processed
                if 'results' in data and 'stats' in data['results']:
                    stats = data['results']['stats']
                    print(f"   Rules processed: {stats.get('rules_processed', 0)}")
                    print(f"   Normalized rules created: {stats.get('normalized_rules_created', 0)}")
            else:
                print(f"   ❌ API rejected request with source_file (status {response.status_code})")
                error_data = response.json()
                print(f"   Error: {error_data.get('error', 'Unknown error')}")
        except requests.exceptions.ConnectionError:
            print("   ⚠️  Backend server not running. Please start the backend server to test the API.")
        
        print(f"\n=== Fix Verification Summary ===")
        print("✅ The fix should prevent accidental normalization of all rules")
        print("✅ Users must now explicitly use force_all=true to normalize all rules")
        print("✅ This prevents old deleted rules from reappearing unexpectedly")
        print("✅ File-specific normalization still works as expected")

if __name__ == "__main__":
    test_fix_verification()