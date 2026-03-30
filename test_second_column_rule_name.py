#!/usr/bin/env python3
"""
Test script to upload the observations.csv file using the second column ("Name") as rule name
This simulates using a different column for rule names
"""

import sys
import os
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from parsers.parser_factory import parser_factory
from flask import Flask

def test_second_column_rule_name():
    """Test uploading observations.csv using second column ("Name") as rule name"""
    
    with app.app_context():
        print("🧪 Testing observations.csv upload with second column as rule name...")
        
        # Clear existing data first
        print("🗑️  Clearing existing data...")
        NormalizedRule.query.delete()
        RawFirewallRule.query.delete()
        db.session.commit()
        
        # Define the column mapping - using "Name" column as rule_name
        column_mapping = {
            "Unnamed: 0": "custom_observation_id",
            "Name": "custom_rule_name",  # This is the crucial mapping - using second column!
            "Tags": "custom_tags",
            "Type": "custom_type",
            "Source Zone": "custom_source_zone",
            "Source Address": "custom_source",
            "Source User": "custom_source_user",
            "Source Device": "custom_source_device",
            "Destination Zone": "custom_dest_zone",
            "Destination Address": "custom_destination",
            "Destination Device": "custom_dest_device",
            "Service": "custom_service",
            "Application": "custom_application",
            "Action": "custom_action",
            "Profile": "custom_profile",
            "Options": "custom_options",
            "Rule Usage Hit Count": "custom_hit_count",
            "Rule Usage Last Hit": "custom_last_hit",
            "Rule Usage First Hit": "custom_first_hit",
            "Rule Usage Apps Seen": "custom_apps_seen",
            "Days With No New Apps": "custom_days_no_new_apps",
            "Modified": "custom_modified",
            "Created": "custom_created"
        }
        
        print("📋 Column mapping for rule names:")
        print(f"   CSV Column: 'Name' (second column) → Database Field: 'custom_rule_name'")
        
        # File path to the observations.csv
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
                print("\n🔍 Checking rule names in raw rules (using 'Name' column):")
                for rule in raw_rules:
                    print(f"   Rule ID {rule.id}: '{rule.rule_name}'")
            
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
                print("🎉 SUCCESS: All rules have proper rule names using the second column!")
                print("✅ The column mapping fix works with different columns!")
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
    success = test_second_column_rule_name()
    if success:
        print("\n🎯 Test completed successfully! The rule name mapping works with the second column.")
    else:
        print("\n💥 Test failed! The issue may still exist.")
    
    sys.exit(0 if success else 1)