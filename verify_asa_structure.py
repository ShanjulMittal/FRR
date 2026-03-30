
import sys
import os
import json

# Add project root to path
sys.path.append('/Users/shanjulmittal/FRR')

from backend.parsers.firewall_parser import FirewallParser

parser = FirewallParser('test_asa_structure.txt', 'firewall')
records = parser.parse()

for r in records:
    if r.get('rule_type') == 'access_list':
        print(f"Rule: {r.get('acl_name')} Line: {r.get('line_number_in_acl')}")
        print(f"  Protocol: {r.get('protocol')}")
        print(f"  Source: {r.get('source')}")
        print(f"  Destination: {r.get('destination')}")
        print(f"  Dest Port: {r.get('dest_port')}")
        print(f"  Name: {r.get('rule_name')}")
    elif r.get('rule_type') == 'object_group':
        pass
        # print(f"ObjectGroup: {r.get('name')} Type: {r.get('type')}")

print(f"Total Records: {len(records)}")
