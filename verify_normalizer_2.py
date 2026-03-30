
import sys
import os
from unittest.mock import MagicMock

# Mocking the environment
sys.path.append(os.path.join(os.getcwd(), 'backend'))

# Mock imports BEFORE importing RuleNormalizer
sys.modules['models'] = MagicMock()
sys.modules['custom_fields_service'] = MagicMock()
# Mock protocol_port_parser to return None, so we test custom logic in RuleNormalizer
m_ppp = MagicMock()
m_ppp.parse_service_field.return_value = None
sys.modules['protocol_port_parser'] = m_ppp

from rule_normalizer import RuleNormalizer

def test_normalizer():
    # Instantiate without arguments
    try:
        norm = RuleNormalizer()
    except Exception as e:
        print(f"Error instantiating RuleNormalizer: {e}")
        return

    test_cases = [
        "135-139",
        "135-netbios-ssn",
        "object-group DHCP_Port",
        "80, 443",
        "TCP-80; UDP-53",
        "range 135 139",
        "bootps-tftp" 
    ]
    
    print("Testing parse_protocol_service_field:")
    for tc in test_cases:
        try:
            # The method calls self._parse_single_service
            res = norm.parse_protocol_service_field(tc)
            print(f"\nInput: '{tc}'")
            for r in res:
                print(f"  Result: {r}")
        except Exception as e:
            print(f"\nInput: '{tc}' -> Error: {e}")

if __name__ == "__main__":
    test_normalizer()
