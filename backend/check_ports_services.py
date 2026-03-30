#!/usr/bin/env python3

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import NormalizedRule, db

def check_ports_and_services():
    """Check if ports and services are properly populated in normalized rules"""
    
    normalized_rules = NormalizedRule.query.all()
    print(f"Total normalized rules: {len(normalized_rules)}")
    
    # Check port information
    print("\nPort information in normalized rules:")
    source_port_none = 0
    dest_port_none = 0
    source_port_populated = 0
    dest_port_populated = 0
    
    for rule in normalized_rules:
        if rule.source_port is None:
            source_port_none += 1
        else:
            source_port_populated += 1
            
        if rule.dest_port is None:
            dest_port_none += 1
        else:
            dest_port_populated += 1
    
    print(f"Source port - None: {source_port_none}, Populated: {source_port_populated}")
    print(f"Dest port - None: {dest_port_none}, Populated: {dest_port_populated}")
    
    # Check service information
    print("\nService information in normalized rules:")
    service_none = 0
    service_populated = 0
    
    for rule in normalized_rules:
        if rule.service_name is None or rule.service_name == "":
            service_none += 1
        else:
            service_populated += 1
    
    print(f"Service name - None/Empty: {service_none}, Populated: {service_populated}")
    
    # Show first 10 rules with port and service details
    print("\nFirst 10 normalized rules with port and service details:")
    for i, rule in enumerate(normalized_rules[:10]):
        print(f"Rule {i+1}:")
        print(f"  Rule Name: {rule.rule_name}")
        print(f"  Source Port: {rule.source_port}")
        print(f"  Dest Port: {rule.dest_port}")
        print(f"  Service Name: {rule.service_name}")
        print(f"  Protocol: {rule.protocol}")
        print()

if __name__ == "__main__":
    from app import app
    with app.app_context():
        check_ports_and_services()