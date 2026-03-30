
import sys
import os
import logging

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from rule_normalizer import RuleNormalizer
from protocol_port_parser import parse_service_field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_normalization_logic():
    print("Testing protocol_port_parser directly:")
    res = parse_service_field("tcp/https")
    print(f"parse_service_field('tcp/https') -> {res}")
    
    res = parse_service_field("HTTPS")
    print(f"parse_service_field('HTTPS') -> {res}")

    print("\nTesting RuleNormalizer logic:")
    normalizer = RuleNormalizer()
    
    # Simulate the logic in normalize_single_rule
    protocol = "tcp"
    dest_port = "https"
    service_field = f"{protocol}/{dest_port}"
    print(f"Constructed service_field: {service_field}")
    
    parsed_services = normalizer.parse_protocol_service_field(service_field)
    print(f"parsed_services: {parsed_services}")
    
    # Check result
    ports = [str(ps['port']) for ps in parsed_services if ps.get('port')]
    print(f"Extracted ports: {ports}")
    
    final_dest_port = (';'.join(ports) if ports else dest_port)
    print(f"Final dest_port: {final_dest_port}")

if __name__ == "__main__":
    test_normalization_logic()
