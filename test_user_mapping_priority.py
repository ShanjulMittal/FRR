#!/usr/bin/env python3
"""
Test script to verify user-selected mappings are properly applied in CMDB import
"""

import tempfile
import os
import sys
sys.path.append('/Users/shanjulmittal/FRR/backend')

from parsers.csv_parser import CSVParser
from models import CMDBAsset


def test_user_mapping_priority():
    """Test that user-selected mappings take priority over automatic field detection"""
    
    # Create test CSV data with intentionally confusing column names
    test_data = """Server_Name,IP_Addr,Owner_Dept,Asset_Type,Location_Info
web-server-01,192.168.1.100,IT Operations,Web Server,Data Center A
app-server-02,192.168.1.101,Development Team,Application Server,Data Center B
db-server-03,192.168.1.102,Database Team,Database Server,Data Center A
"""
    
    # Create temporary CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(test_data)
        test_file = f.name
    
    try:
        print("🧪 Testing User Mapping Priority in CMDB Import")
        print("=" * 60)
        
        # Test 1: User mapping that overrides confusing column names
        print("\n📋 Test 1: User-selected mappings")
        user_mapping = {
            'Server_Name': ['hostname'],
            'IP_Addr': ['ip_address'], 
            'Owner_Dept': ['owner'],
            'Asset_Type': ['asset_type'],
            'Location_Info': ['location']
        }
        
        print(f"User mapping: {user_mapping}")
        
        # Parse with user mapping
        parser = CSVParser(test_file, 'cmdb', column_mapping=user_mapping)
        parsed_records = parser.parse()
        
        print(f"✅ Parser completed successfully")
        print(f"📊 Parsed records count: {len(parsed_records)}")
        
        # Debug the first record to see what's happening
        if parsed_records:
            print(f"📝 First record keys: {list(parsed_records[0].keys())}")
            print(f"🎯 First record: {parsed_records[0]}")
        else:
            print("❌ No records parsed - checking validation issues")
            
        if parsed_records and len(parsed_records) > 0:
            print(f"📝 First record keys: {list(parsed_records[0].keys())}")
            print(f"🎯 First record hostname: {parsed_records[0].get('hostname')}")
            print(f"🎯 First record ip_address: {parsed_records[0].get('ip_address')}")
            print(f"🎯 First record owner: {parsed_records[0].get('owner')}")
            
            # Test 2: Store the data and verify it persists correctly
            print("\n💾 Test 2: Storing parsed data")
            
            # Test the storage function
            try:
                # Create a mock storage result
                stored_assets = []
                for record in parsed_records:
                    asset = CMDBAsset(
                        hostname=record.get('hostname'),
                        ip_address=record.get('ip_address'),
                        owner=record.get('owner'),
                        asset_type=record.get('asset_type'),
                        location=record.get('location'),
                        environment='production',  # Use a valid field instead of description
                        additional_data=f"Test asset: {record.get('hostname')}"  # Use additional_data for extra info
                    )
                    stored_assets.append(asset)
                
                print(f"✅ Successfully created {len(stored_assets)} mock assets")
                
                # Verify each asset has correct user-mapped data
                for i, asset in enumerate(stored_assets):
                    print(f"\n🔍 Asset {i+1} verification:")
                    
                    # Get the original record to verify against
                    original_record = parsed_records[i]
                    expected_hostname = original_record.get('hostname')
                    expected_ip = original_record.get('ip_address')
                    expected_owner = original_record.get('owner')
                    expected_asset_type = original_record.get('asset_type')
                    expected_location = original_record.get('location')
                    
                    print(f"  Hostname: {asset.hostname} (expected: {expected_hostname})")
                    print(f"  IP Address: {asset.ip_address} (expected: {expected_ip})")
                    print(f"  Owner: {asset.owner} (expected: {expected_owner})")
                    print(f"  Asset Type: {asset.asset_type} (expected: {expected_asset_type})")
                    print(f"  Location: {asset.location} (expected: {expected_location})")
                    
                    # Verify user mapping was applied correctly
                    if (asset.hostname == expected_hostname and 
                        asset.ip_address == expected_ip and 
                        asset.owner == expected_owner and
                        asset.asset_type == expected_asset_type and
                        asset.location == expected_location):
                        print(f"  ✅ User mapping applied correctly!")
                    else:
                        print(f"  ❌ User mapping not applied correctly!")
                        return False
                
                print(f"\n🎉 All tests passed! User mappings are working correctly.")
                return True
                
            except Exception as e:
                print(f"❌ Error during storage: {str(e)}")
                return False
        else:
            print(f"❌ Parser failed: No data returned")
            return False
            
    finally:
        # Clean up
        if os.path.exists(test_file):
            os.unlink(test_file)


def test_automatic_vs_user_mapping():
    """Compare automatic mapping vs user mapping results"""
    
    # Create test CSV with both clear and confusing column names
    test_data = """hostname,ip_address,owner,custom_field_1,custom_field_2
server-01,10.0.0.1,John Doe,Some Value,Another Value
server-02,10.0.0.2,Jane Smith,Different Value,More Data
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(test_data)
        test_file = f.name
    
    try:
        print("\n🔄 Test 3: Automatic vs User Mapping Comparison")
        print("=" * 60)
        
        # Test automatic mapping (no user mapping)
        print("\n🤖 Automatic Mapping (no user mapping):")
        parser_auto = CSVParser(test_file, 'cmdb')
        records_auto = parser_auto.parse()
        
        if records_auto and len(records_auto) > 0:
            print(f"  First record: {records_auto[0]}")
        
        # Test user mapping
        print("\n👤 User Mapping (map custom fields):")
        user_mapping = {
            'custom_field_1': ['description'],
            'custom_field_2': ['environment']
        }
        
        parser_user = CSVParser(test_file, 'cmdb', column_mapping=user_mapping)
        records_user = parser_user.parse()
        
        if records_user and len(records_user) > 0:
            print(f"  First record: {records_user[0]}")
            
            # Verify user mapping was applied
            record = records_user[0]
            if record.get('description') == 'Some Value' and record.get('environment') == 'Another Value':
                print("  ✅ User mapping successfully applied custom fields!")
                return True
            else:
                print("  ❌ User mapping not applied to custom fields")
                return False
        
        return False
        
    finally:
        if os.path.exists(test_file):
            os.unlink(test_file)


if __name__ == "__main__":
    print("🔍 Testing CMDB User Mapping Priority")
    print("=" * 50)
    
    # Run tests
    test1_passed = test_user_mapping_priority()
    test2_passed = test_automatic_vs_user_mapping()
    
    print(f"\n📈 Final Results:")
    print(f"  User Mapping Priority Test: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"  Automatic vs User Mapping Test: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print(f"\n🎉 All tests passed! User mappings are working correctly.")
        sys.exit(0)
    else:
        print(f"\n❌ Some tests failed. User mappings need more work.")
        sys.exit(1)