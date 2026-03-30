
import sys
import os
from unittest.mock import MagicMock

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

# Mock database
sys.modules['models'] = MagicMock()
sys.modules['custom_fields_service'] = MagicMock()

from parsers.firewall_parser import FirewallParser

def test_parsing():
    lines = [
        "access-list INSIDE line 34 extended permit object-group DR_TM_Control_Services object DR_TM_Control_Manager object-group TCS-Mum_Subnet (hitcnt=0) 0x2d90e604",
        "access-list INSIDE line 35 extended permit object-group DR_TM_Scan_Services object DR_TM_Scan_Server object-group TCS-Mum_Subnet (hitcnt=0) 0x0b51f8d6",
        "access-list INSIDE line 36 extended permit tcp object DR_EP_Encryption_Server object-group TCS-Mum_Subnet eq www (hitcnt=0) 0xd3cd6994",
        "access-list INSIDE line 38 extended permit object-group TM_Smart_Protection_Services object TM_Smart_Protection_Server object-group TCS-Mum_Subnet (hitcnt=0) 0xfa3f0c4f",
        "access-list OUTSIDE line 444 extended permit tcp object-group TCS-Mum_Subnet object-group STS_SBIC eq https (hitcnt=592) 0x6081fe5e",
        "access-list OUTSIDE line 446 extended permit object-group TrendMicro_Port object-group TCS-Mum_Subnet object-group TrendMicro_AV-Svr1 (hitcnt=9294) 0x861edaf3"
    ]
    
    # Write to temp file
    temp_file = "temp_reproduce_4.conf"
    with open(temp_file, "w") as f:
        f.write("\n".join(lines))
    
    parser = FirewallParser(os.path.abspath(temp_file), "firewall")
    
    print(f"Testing {len(lines)} lines from {temp_file}...")
    
    records = parser.parse()
    
    for r in records:
        if r.get('rule_type') == 'access_list':
            print(f"\nRule: {r['raw_text']}")
            print(f"  Proto: {r['protocol']}")
            print(f"  Source: {r['source']}")
            print(f"  Dest: {r['destination']}")
            print(f"  Dest Port: {r.get('dest_port')}")
            print(f"  HitCount: {r.get('hit_count')}")

if __name__ == "__main__":
    test_parsing()
