import sys
import os
import re

# Mocking the FirewallParser environment
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from parsers.firewall_parser import FirewallParser

def test_parser():
    config = """
object-group service DHCP_Port udp
 port-object eq bootps
 port-object eq tftp
object-group network SBIC_DHCP
 network-object host 1.1.1.1
object-group network TCSMum_Unauth_NAC
 network-object host 2.2.2.2

access-list INSIDE line 66 extended permit object-group DHCP_Port object-group SBIC_DHCP object-group TCSMum_Unauth_NAC (hitcnt=0)
access-list INSIDE line 66 extended permit udp host 172.30.53.74 172.18.209.0 255.255.255.128 range bootps tftp (hitcnt=0)
"""
    # Create a temp file.
    with open("temp_test_config_3.conf", "w") as f:
        f.write(config)
        
    parser = FirewallParser(os.path.abspath("temp_test_config_3.conf"), "firewall")
    # Original issue rule
    rule_text = "access-list INSIDE line 66 extended permit object-group DHCP_Port object-group SBIC_DHCP object-group TCSMum_Unauth_NAC (hitcnt=0)"
    
    match = parser.CISCO_ASA_PATTERNS['access_list'].match(rule_text)
    if match:
        result = parser._parse_access_list_rule(match, rule_text, 66)
        print(f"Rule: {rule_text}")
        print(f"  Proto: {result.get('protocol')}")
        print(f"  Source: {result.get('source')}")
        print(f"  Dest: {result.get('destination')}")
        print(f"  Dest Port: {result.get('dest_port')}")
    else:
        print("No match!")

    # Range issue rule
    rule_text_2 = "access-list INSIDE line 66 extended permit tcp host 172.30.53.74 172.18.209.0 255.255.255.128 range 135 netbios-ssn (hitcnt=0)"
    match_2 = parser.CISCO_ASA_PATTERNS['access_list'].match(rule_text_2)
    if match_2:
        result = parser._parse_access_list_rule(match_2, rule_text_2, 66)
        print(f"\nRule: {rule_text_2}")
        print(f"  Proto: {result.get('protocol')}")
        print(f"  Source: {result.get('source')}")
        print(f"  Dest: {result.get('destination')}")
        print(f"  Dest Port: {result.get('dest_port')}")
    else:
        print("No match for range rule!")

    os.remove("temp_test_config_3.conf")

if __name__ == "__main__":
    test_parser()
