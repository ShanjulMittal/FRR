#!/usr/bin/env python3
"""
Debug script to test CMDB mapping functionality
"""
import json
import pandas as pd
import sys
sys.path.append('/Users/shanjulmittal/FRR/backend')
from parsers.csv_parser import CSVParser

# Create a simple test CSV
test_data = {
    'Server Name': ['server1', 'server2'],
    'IP Address': ['192.168.1.1', '192.168.1.2'],
    'Owner': ['John', 'Jane'],
    'Department': ['IT', 'HR']
}

df = pd.DataFrame(test_data)
test_file = '/tmp/test_cmdb.csv'
df.to_csv(test_file, index=False)

print("=== Test CSV Content ===")
print(df)
print()

# Test with user mapping
user_mapping = {
    'Server Name': ['hostname'],
    'IP Address': ['ip_address'],
    'Owner': ['owner'],
    'Department': ['department']
}

print("=== User Mapping ===")
print(json.dumps(user_mapping, indent=2))
print()

# Test the parser
parser = CSVParser(test_file, 'cmdb', column_mapping=user_mapping)
result = parser.parse()

print("=== Parsed Result ===")
for i, record in enumerate(result[:2]):
    print(f"Record {i+1}:")
    for key, value in record.items():
        if not key.startswith('_'):
            print(f"  {key}: {value}")
    if '_mapped_fields' in record:
        print(f"  _mapped_fields: {record['_mapped_fields']}")
    print()

print("=== Expected vs Actual ===")
print("Expected fields: hostname, ip_address, owner, department")
actual_fields = set()
for record in result[:1]:
    for key in record.keys():
        if not key.startswith('_'):
            actual_fields.add(key)
print(f"Actual fields: {list(actual_fields)}")