#!/usr/bin/env python3
"""
Verification script to show multi-service normalization results
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import RawFirewallRule, NormalizedRule, db

def verify_multi_service_results():
    """Verify that multi-service rules are properly normalized"""
    
    with app.app_context():
        print("=== Multi-Service Normalization Verification ===\n")
        
        # Find raw rules with multi-service protocols
        multi_service_raw_rules = db.session.query(RawFirewallRule).filter(
            RawFirewallRule.protocol.contains(';')
        ).all()
        
        print(f"Found {len(multi_service_raw_rules)} raw rules with multi-service protocols\n")
        
        for raw_rule in multi_service_raw_rules:
            print(f"Raw Rule ID: {raw_rule.id}")
            print(f"  Protocol Field: '{raw_rule.protocol}'")
            print(f"  Source: {raw_rule.source}")
            print(f"  Destination: {raw_rule.destination}")
            print(f"  Action: {raw_rule.action}")
            
            # Find all normalized rules created from this raw rule
            normalized_rules = db.session.query(NormalizedRule).filter(
                NormalizedRule.raw_rule_id == raw_rule.id
            ).all()
            
            print(f"  Normalized into {len(normalized_rules)} rule(s):")
            
            for i, norm_rule in enumerate(normalized_rules, 1):
                print(f"    Rule {i}:")
                print(f"      ID: {norm_rule.id}")
                print(f"      Protocol: {norm_rule.protocol}")
                print(f"      Destination Port: {norm_rule.dest_port}")
                print(f"      Service Name: {norm_rule.service_name}")
                print(f"      Risk Level: {norm_rule.risk_level}")
            
            print("-" * 60)
        
        # Summary statistics
        total_raw_rules = db.session.query(RawFirewallRule).count()
        total_normalized_rules = db.session.query(NormalizedRule).count()
        
        print(f"\n=== Summary Statistics ===")
        print(f"Total Raw Rules: {total_raw_rules}")
        print(f"Total Normalized Rules: {total_normalized_rules}")
        print(f"Expansion Ratio: {total_normalized_rules/total_raw_rules:.2f}x")
        
        # Show some examples of single vs multi-service expansion
        print(f"\nMulti-service rules found: {len(multi_service_raw_rules)}")
        
        single_service_count = total_raw_rules - len(multi_service_raw_rules)
        print(f"Single-service rules: {single_service_count}")

if __name__ == "__main__":
    verify_multi_service_results()