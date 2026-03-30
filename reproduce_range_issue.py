
import sys
import os
# Add project root to path
sys.path.append(os.getcwd())
# Add backend to path (for internal imports within backend modules)
sys.path.append(os.path.join(os.getcwd(), 'backend'))

try:
    from backend.parsers.firewall_parser import FirewallParser
except ImportError:
    try:
        from parsers.firewall_parser import FirewallParser
    except ImportError:
        print("Could not import FirewallParser. Check paths.")
        sys.exit(1)

import json

import tempfile

def test_range_parsing():
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp:
        tmp.write("access-list TEST line 1 extended permit ip range 10.10.10.1 10.10.10.5 any\n")
        tmp_path = tmp.name

    try:
        parser = FirewallParser(tmp_path, "cisco_asa")
        print(f"Parsing file: {tmp_path}")
        parsed_rules = parser.parse()
        
        for rule in parsed_rules:
            # parsed_rules is a list of dicts, not objects
            print("\nParsed Rule:")
            print(f"Source: {rule.get('source')}")
            print(f"Destination: {rule.get('destination')}")
            details = rule.get('details', [])
            print(f"Details: {details}")
            
            # Simulate RuleNormalizer extraction logic
            for d in details:
                s = d.get('source', '')
                raw_text = d.get('raw_text', '')
                print(f"Detail Source: '{s}'")
                print(f"Detail Raw Text: '{raw_text}'")
                
                if s == 'range':
                    import re
                    m = re.search(r"\brange\s+((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})", raw_text)
                    if m:
                        print(f"Extracted Range: {m.group(1)}-{m.group(2)}")
                    else:
                        print("Failed to extract range from raw_text")
    finally:
        os.remove(tmp_path)


if __name__ == "__main__":
    test_range_parsing()
