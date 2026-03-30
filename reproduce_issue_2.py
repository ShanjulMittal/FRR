import sys
import os
import re

# Mocking the FirewallParser environment
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from parsers.firewall_parser import FirewallParser

def test_parser():
    # Case 1: Implicit object-group (missing 'object-group' keyword)
    # AND definition is after the rule.
    config = """
access-list test extended permit Spine_Webserver object-group SRC object-group DST (hitcnt=100)

object-group service Spine_Webserver tcp
 port-object eq 80
object-group network SRC
 network-object host 1.1.1.1
object-group network DST
 network-object host 2.2.2.2
"""
    # Create a temp file.
    with open("temp_test_config_2.conf", "w") as f:
        f.write(config)
        
    parser = FirewallParser(os.path.abspath("temp_test_config_2.conf"), "firewall")
    records = parser.parse()
    
    found_failure = False
    
    for r in records:
        if r['rule_type'] == 'access_list':
            print(f"Rule: {r['raw_text']}")
            print(f"  Proto: {r['protocol']}")
            print(f"  Source: {r['source']}")
            print(f"  Dest: {r['destination']}")
            
            if "Spine_Webserver" in r['raw_text']:
                if r['protocol'] == 'ip' and r['source'] == 'Spine_Webserver':
                    print("  -> REPRODUCED: Parsed as IP/Source because 'object-group' keyword missing and definition late.")
                    found_failure = True
                elif r['protocol'] == 'Spine_Webserver' or r['protocol'] == 'object-group Spine_Webserver':
                    print("  -> PASSED: Correctly identified as protocol.")

    if found_failure:
        print("\nIssue Reproduced!")
    else:
        print("\nCould not reproduce.")
    
    os.remove("temp_test_config_2.conf")

if __name__ == "__main__":
    test_parser()
