#!/usr/bin/env python3
"""
Test script to upload observations.csv with proper column mapping to verify the fix
"""

import os
import sys
import json

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app import app, db
from models import RawFirewallRule, NormalizedRule

def test_upload_with_mapping():
    """Test uploading observations.csv with proper column mapping"""
    
    with app.app_context():
        # Clear existing data first
        print("Clearing existing data...")
        NormalizedRule.query.delete()
        RawFirewallRule.query.delete()
        db.session.commit()
        
        # Test file path
        csv_file_path = '/Users/shanjulmittal/FRR/test-files/observations.csv'
        
        # Column mapping that should map the actual columns to firewall rule fields
        column_mapping = {
            'Name': 'rule_name',           # Map 'Name' column to 'rule_name'
            'Source Address': 'source',    # Map 'Source Address' column to 'source'
            'Destination Address': 'destination',  # Map 'Destination Address' column to 'destination'
            'Service': 'service',          # Map 'Service' column to 'service'
            'Action': 'action',            # Map 'Action' column to 'action'
            # Note: There's no 'Protocol' column in this file, so we'll map Service to both service and protocol
        }
        
        print(f"Testing upload with column mapping: {column_mapping}")
        
        # Use parser factory to parse the file with column mapping
        from parsers.parser_factory import parser_factory
        
        try:
            parsed_data = parser_factory.parse_file(
                csv_file_path, 
                'firewall', 
                column_mapping=column_mapping
            )
            print(f"Successfully parsed {len(parsed_data)} records")
            
            # Check if rule_name is present in parsed data
            if parsed_data:
                first_record = parsed_data[0]
                print(f"First record keys: {list(first_record.keys())}")
                if 'rule_name' in first_record:
                    print(f"First record rule_name: '{first_record['rule_name']}'")
                else:
                    print("ERROR: rule_name not found in parsed data!")
                    return False
            
            # Store parsed data
            from app import store_parsed_data
            records_processed = store_parsed_data(parsed_data, 'firewall', 'observations.csv')
            print(f"Stored {records_processed} raw firewall rules")
            
            # Check if rule names were stored
            raw_rules_with_names = RawFirewallRule.query.filter(RawFirewallRule.rule_name.isnot(None)).all()
            print(f"Raw rules with rule_name: {len(raw_rules_with_names)}")
            
            if raw_rules_with_names:
                print("Sample rule names from raw rules:")
                for rule in raw_rules_with_names[:5]:  # Show first 5
                    print(f"  - ID: {rule.id}, Rule Name: '{rule.rule_name}'")
                return True
            else:
                print("ERROR: No rule names found in database!")
                return False
                
        except Exception as e:
            print(f"Error during parsing: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = test_upload_with_mapping()
    if success:
        print("\n✅ Test passed! Rule names are being stored correctly.")
    else:
        print("\n❌ Test failed! Rule names are not being stored.")
    sys.exit(0 if success else 1)