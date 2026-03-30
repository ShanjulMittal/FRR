#!/usr/bin/env python3
"""
Test script to verify multi-service parsing functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rule_normalizer import RuleNormalizer
from models import RawFirewallRule, NormalizedRule, db
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

def test_multi_service_parsing():
    """Test the enhanced multi-service parsing functionality"""
    
    print("=== Testing Multi-Service Parsing ===\n")
    
    # Initialize the normalizer
    normalizer = RuleNormalizer()
    
    # Test cases for multi-service parsing
    test_cases = [
        "HTTPS;TCP-2021",
        "SSH;TCP-2202;TCP-1860", 
        "TCP-80;UDP-53;TCP-443",
        "HTTP;HTTPS;FTP",
        "TCP-22;UDP-161;TCP-3389",
        "SERVICE-WEB;SERVICE-DB;SERVICE-SSH",
        "80/tcp;443/tcp;22/tcp",
        "tcp:80;udp:53;tcp:443"
    ]
    
    print("Testing parse_protocol_service_field method:\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: '{test_case}'")
        try:
            parsed_services = normalizer.parse_protocol_service_field(test_case)
            print(f"  Result: {len(parsed_services)} service(s) parsed")
            for j, service in enumerate(parsed_services):
                print(f"    Service {j+1}: Protocol={service['protocol']}, Port={service['port']}, Name={service['service_name']}")
        except Exception as e:
            print(f"  ERROR: {str(e)}")
        print()
    
    # Test with actual database rules if available
    print("\n=== Testing with Database Rules ===\n")
    
    try:
        # Query some multi-service rules from the database
        multi_service_rules = db.session.query(RawFirewallRule).filter(
            RawFirewallRule.protocol.contains(';')
        ).limit(5).all()
        
        if multi_service_rules:
            print(f"Found {len(multi_service_rules)} multi-service rules in database\n")
            
            for rule in multi_service_rules:
                print(f"Raw Rule ID: {rule.id}")
                print(f"  Protocol field: '{rule.protocol}'")
                print(f"  Source: {rule.source} -> Destination: {rule.destination}")
                
                try:
                    # Test normalization
                    normalized_rules = normalizer.normalize_single_rule(rule)
                    print(f"  Normalized into {len(normalized_rules)} rule(s):")
                    
                    for i, norm_rule in enumerate(normalized_rules):
                        print(f"    Rule {i+1}: Protocol={norm_rule.protocol}, Port={norm_rule.dest_port}, Service={norm_rule.service_name}")
                        
                except Exception as e:
                    print(f"  ERROR during normalization: {str(e)}")
                print()
        else:
            print("No multi-service rules found in database")
            
    except Exception as e:
        print(f"Database query error: {str(e)}")

def test_single_service_compatibility():
    """Test that single service parsing still works correctly"""
    
    print("\n=== Testing Single Service Compatibility ===\n")
    
    normalizer = RuleNormalizer()
    
    single_service_cases = [
        "TCP-80",
        "UDP-53", 
        "HTTPS",
        "SSH",
        "80/tcp",
        "tcp:443",
        "SERVICE-WEB"
    ]
    
    for test_case in single_service_cases:
        print(f"Testing: '{test_case}'")
        try:
            parsed_services = normalizer.parse_protocol_service_field(test_case)
            print(f"  Result: {len(parsed_services)} service(s) - should be 1")
            if parsed_services:
                service = parsed_services[0]
                print(f"    Protocol={service['protocol']}, Port={service['port']}, Name={service['service_name']}")
        except Exception as e:
            print(f"  ERROR: {str(e)}")
        print()

if __name__ == "__main__":
    print("Multi-Service Parsing Test Suite")
    print("=" * 50)
    
    test_multi_service_parsing()
    test_single_service_compatibility()
    
    print("\n" + "=" * 50)
    print("Test completed!")