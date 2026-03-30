#!/usr/bin/env python3
"""
Test script to upload the original observations.csv file with proper column mapping
This simulates the exact user workflow to ensure rule names are correctly stored
"""

import sys
import os
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from parsers.parser_factory import parser_factory
from flask import Flask

def test_original_upload():
    """Test uploading the original observations.csv with proper column mapping"""
    
    with app.app_context():
        print("🧪 Testing original observations.csv upload with proper column mapping...")
        
        # Clear existing data first
        print("🗑️  Clearing existing data...")
        NormalizedRule.query.delete()
        RawFirewallRule.query.delete()
        db.session.commit()
        
        # Define the column mapping that should be used
        column_mapping = {
            "Observation ID": "custom_observation_id",
            "Source": "custom_source",
            "Destination": "custom_destination", 
            "Src Port": "custom_source_port",
            "Dst Port": "custom_dest_port",
            "Proto": "custom_protocol",
            "Decision": "custom_action",
            "Rule Name": "custom_rule_name",  # This is the crucial mapping!
            "Line": "custom_line_number",
            "Type": "custom_rule_type"
        }
        
        print("📋 Column mapping for rule names:")
        print(f"   CSV Column: 'Rule Name' → Database Field: 'custom_rule_name'")
        
        # File path to the original observations.csv
        file_path = "/Users/shanjulmittal/FRR/test-files/observations.csv"
        
        print(f"📁 Uploading file: {file_path}")
        
        try:
            # Parse the file using the parser factory
            parsed_data = parser_factory.parse_file(file_path, 'firewall', column_mapping=column_mapping)
            
            print(f"✅ File parsed successfully: {len(parsed_data)} records")
            
            # Store the parsed data
            from app import store_parsed_data
            store_parsed_data(parsed_data, 'firewall', 'observations.csv')
            
            print("✅ Data stored in database")
            
            # Verify raw rules were created with rule names
            raw_rules = RawFirewallRule.query.all()
            print(f"📊 Raw rules in database: {len(raw_rules)}")
            
            if raw_rules:
                print("\n🔍 Checking rule names in raw rules:")
                for rule in raw_rules:
                    print(f"   Rule ID {rule.id}: '{rule.rule_name}' (Raw Rule ID: {rule.id})")
            
            # Run normalization
            print("\n🔄 Running rule normalization...")
            from rule_normalizer import RuleNormalizer
            normalizer = RuleNormalizer()
            normalizer.normalize_all_rules()
            
            # Check normalized rules
            normalized_rules = NormalizedRule.query.all()
            print(f"📊 Normalized rules: {len(normalized_rules)}")
            
            if normalized_rules:
                print("\n🔍 Checking rule names in normalized rules:")
                for rule in normalized_rules:
                    raw_rule = RawFirewallRule.query.get(rule.raw_rule_id)
                    print(f"   Normalized Rule ID {rule.id}: '{rule.rule_name}' (Raw Rule ID: {rule.raw_rule_id}, Raw Rule Name: '{raw_rule.rule_name if raw_rule else 'N/A'}')")
            
            # Final verification
            print("\n✅ FINAL VERIFICATION:")
            
            # Check if all rules have proper names
            rules_without_names = RawFirewallRule.query.filter(RawFirewallRule.rule_name.is_(None)).count()
            normalized_without_names = NormalizedRule.query.filter(NormalizedRule.rule_name.is_(None)).count()
            
            print(f"   Raw rules without names: {rules_without_names}")
            print(f"   Normalized rules without names: {normalized_without_names}")
            
            if rules_without_names == 0 and normalized_without_names == 0:
                print("🎉 SUCCESS: All rules have proper rule names!")
                print("✅ The column mapping fix is working correctly!")
                return True
            else:
                print("❌ FAILURE: Some rules are missing names")
                return False
                
        except Exception as e:
            print(f"❌ Error during upload test: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/shanjulmittal/FRR/backend/firewall_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

if __name__ == "__main__":
    success = test_original_upload()
    if success:
        print("\n🎯 Test completed successfully! The rule name mapping issue has been fixed.")
    else:
        print("\n💥 Test failed! The issue may still exist.")
    
    sys.exit(0 if success else 1)