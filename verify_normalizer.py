import sys
import os
from unittest.mock import MagicMock

# Mocking the environment
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from rule_normalizer import RuleNormalizer
from models import RawFirewallRule, NormalizedRule

def test_normalization():
    # Mock dependencies
    db_session = MagicMock()
    custom_fields_service = MagicMock()
    custom_fields_service.get_all_fields.return_value = []
    
    normalizer = RuleNormalizer(db_session, custom_fields_service)
    
    # Test case 1: Hit Count propagation with expand_services=True
    # (assuming expand_services is an instance attribute or passed somehow? 
    # Wait, looking at code, it seems self.expand_services is used)
    
    normalizer.expand_services = True # Set flag manually if possible
    
    raw_rule = RawFirewallRule(
        id=1,
        rule_name="TestRule",
        action="permit",
        source="1.1.1.1",
        destination="2.2.2.2",
        protocol="tcp",
        dest_port="80",
        hit_count=500,
        source_file="test.conf"
    )
    
    # We need to mock _expand_service_object_groups to return something simple
    # so logic enters the loop
    normalizer._expand_service_object_groups = MagicMock(return_value=[
        {'protocol': 'tcp', 'port': '80', 'service_name': 'http'}
    ])
    
    # Also need to mock other internal methods that might fail without DB
    normalizer.expand_object_group_field = MagicMock(return_value=[])
    normalizer.is_object_group = MagicMock(return_value=False)
    normalizer.enrich_ip_data = MagicMock(return_value={
        'hostname': None, 'owner': None, 'business_unit': None, 
        'environment': None, 'vlan_id': None, 'vlan_name': None, 'network_segment': None
    })
    normalizer.parse_protocol_service_field = MagicMock(return_value=[
         {'protocol': 'tcp', 'port': '80', 'service_name': 'http'}
    ])
    
    normalized = normalizer.normalize_single_rule(raw_rule)
    
    print(f"Normalized rules count: {len(normalized)}")
    if len(normalized) > 0:
        nr = normalized[0]
        print(f"Hit Count: {nr.hit_count}")
        if nr.hit_count == 500:
            print("PASSED: Hit Count propagated correctly.")
        else:
            print("FAILED: Hit Count mismatch.")
    else:
        print("FAILED: No normalized rules produced.")

if __name__ == "__main__":
    test_normalization()
