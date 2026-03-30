#!/usr/bin/env python3
"""
Test script to verify multi-service normalization with actual database rules
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from rule_normalizer import RuleNormalizer
from models import RawFirewallRule, NormalizedRule, db

def test_normalization_with_database():
    """Test normalization with actual database rules"""
    
    with app.app_context():
        print("=== Testing Normalization with Database Rules ===\n")
        
        # Initialize the normalizer
        normalizer = RuleNormalizer()
        
        # Query some multi-service rules from the database
        multi_service_rules = db.session.query(RawFirewallRule).filter(
            RawFirewallRule.protocol.contains(';')
        ).limit(3).all()
        
        if multi_service_rules:
            print(f"Found {len(multi_service_rules)} multi-service rules in database\n")
            
            for rule in multi_service_rules:
                print(f"Raw Rule ID: {rule.id}")
                print(f"  Protocol field: '{rule.protocol}'")
                print(f"  Source: {rule.source} -> Destination: {rule.destination}")
                print(f"  Action: {rule.action}")
                
                try:
                    # Test normalization
                    normalized_rules = normalizer.normalize_single_rule(rule)
                    print(f"  Normalized into {len(normalized_rules)} rule(s):")
                    
                    for i, norm_rule in enumerate(normalized_rules):
                        print(f"    Rule {i+1}:")
                        print(f"      Protocol: {norm_rule.protocol}")
                        print(f"      Dest Port: {norm_rule.dest_port}")
                        print(f"      Service Name: {norm_rule.service_name}")
                        print(f"      Risk Level: {norm_rule.risk_level}")
                        
                except Exception as e:
                    print(f"  ERROR during normalization: {str(e)}")
                    import traceback
                    traceback.print_exc()
                print("-" * 50)
        else:
            print("No multi-service rules found in database")
            
        # Also test some single service rules for comparison
        print("\n=== Testing Single Service Rules for Comparison ===\n")
        
        single_service_rules = db.session.query(RawFirewallRule).filter(
            ~RawFirewallRule.protocol.contains(';')
        ).limit(2).all()
        
        for rule in single_service_rules:
            print(f"Raw Rule ID: {rule.id}")
            print(f"  Protocol field: '{rule.protocol}'")
            
            try:
                normalized_rules = normalizer.normalize_single_rule(rule)
                print(f"  Normalized into {len(normalized_rules)} rule(s) (should be 1)")
                
                if normalized_rules:
                    norm_rule = normalized_rules[0]
                    print(f"    Protocol: {norm_rule.protocol}, Port: {norm_rule.dest_port}")
                    
            except Exception as e:
                print(f"  ERROR: {str(e)}")
            print()

if __name__ == "__main__":
    print("Multi-Service Normalization Test with Database")
    print("=" * 60)
    
    test_normalization_with_database()
    
    print("\n" + "=" * 60)
    print("Test completed!")