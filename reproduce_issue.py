import sys
import os
import re

# Mocking the FirewallParser environment
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from parsers.firewall_parser import FirewallParser

def test_parser():
    # Object groups AFTER ACLs
    config = """
access-list test extended permit object-group Spine_Webserver object-group SRC object-group DST (hitcnt=100)
access-list test extended permit ip object-group SRC object-group DST

object-group service Spine_Webserver tcp
 port-object eq 80
object-group network SRC
 network-object host 1.1.1.1
object-group network DST
 network-object host 2.2.2.2
"""
    # Create a temp file.
    with open("temp_test_config.conf", "w") as f:
        f.write(config)
        
    parser = FirewallParser(os.path.abspath("temp_test_config.conf"), "firewall")
    records = parser.parse()
    
    found_fixed = False
    
    for r in records:
        if r['rule_type'] == 'access_list':
            print(f"Rule: {r['raw_text']}")
            print(f"  Proto: {r['protocol']}")
            print(f"  Source: {r['source']}")
            print(f"  Dest: {r['destination']}")
            print(f"  HitCount: {r['hit_count']}")
            
            if "Spine_Webserver" in r['raw_text']:
                # If it was fixed by post-processing, protocol should be the group
                if r['protocol'] == 'object-group Spine_Webserver' and \
                   r['source'] == 'object-group SRC' and \
                   r['destination'] == 'object-group DST':
                    print("  -> PASSED: Service Group Mapping fixed by post-processing")
                    found_fixed = True
                elif r['protocol'] == 'ip' and r['source'] == 'object-group Spine_Webserver':
                    print("  -> FAILED: Service Group parsed as Source with IP protocol")
                else:
                    print(f"  -> UNEXPECTED: Proto={r['protocol']}, Src={r['source']}")

    if found_fixed:
        print("\nTest passed!")
    else:
        print("\nTest failed.")
    
    os.remove("temp_test_config.conf")

if __name__ == "__main__":
    test_parser()
