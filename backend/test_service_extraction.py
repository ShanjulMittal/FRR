#!/usr/bin/env python3
"""
Test script to properly extract service information from observations.csv
with correct column mapping for the Service column.
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parsers.parser_factory import parser_factory

def test_service_extraction():
    """Test service information extraction with proper column mapping"""
    
    # File path to observations.csv
    csv_file = os.path.join(os.path.dirname(__file__), '..', 'test-files', 'observations.csv')
    
    # Proper column mapping - map "Service" column to "service" field
    column_mapping = {
        'Service': 'service'
    }
    
    print(f"Testing service extraction from: {csv_file}")
    print(f"Column mapping: {column_mapping}")
    
    try:
        # Parse the CSV with proper column mapping
        parser = parser_factory.get_parser(
            csv_file, 
            'firewall', 
            column_mapping=column_mapping
        )
        
        records = parser.parse()
        
        print(f"\nSuccessfully parsed {len(records)} records")
        print("\nFirst 10 records with service information:")
        
        for i, record in enumerate(records[:10]):
            print(f"\nRecord {i+1}:")
            print(f"  Rule Name: {record.get('rule_name', 'N/A')}")
            print(f"  Protocol: {record.get('protocol', 'N/A')}")
            print(f"  Source Port: {record.get('source_port', 'N/A')}")
            print(f"  Dest Port: {record.get('dest_port', 'N/A')}")
            print(f"  Service: {record.get('service', 'N/A')}")
            print(f"  Service Name: {record.get('service_name', 'N/A')}")
    
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_service_extraction()