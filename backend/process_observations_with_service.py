#!/usr/bin/env python3
"""
Script to properly process observations.csv with service information
and store in the database with correct port information.
"""

import os
import sys
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parsers.parser_factory import parser_factory
from models import db, RawFirewallRule
from rule_normalizer import RuleNormalizer

def process_observations_with_service():
    """Process observations.csv with proper service column mapping"""
    
    # File path to observations.csv
    csv_file = os.path.join(os.path.dirname(__file__), '..', 'test-files', 'observations.csv')
    
    # Proper column mapping - map source, destination, action, and service fields
    column_mapping = {
        'Service': 'service',
        'Name': 'rule_name',
        'Action': 'action',                   # Map to RawFirewallRule.action field
        'Source Address': 'source',           # Map to RawFirewallRule.source field
        'Source Zone': 'source_environment',  # Zone maps to environment
        'Source User': 'source_owner',        # User maps to owner
        'Source Device': 'source_hostname',   # Device maps to hostname
        'Destination Address': 'destination', # Map to RawFirewallRule.destination field
        'Destination Zone': 'dest_environment',  # Zone maps to environment
        'Destination Device': 'dest_hostname'      # Device maps to hostname
    }
    
    print(f"Processing observations.csv with service mapping...")
    print(f"File: {csv_file}")
    print(f"Column mapping: {column_mapping}")
    
    try:
        # Initialize database
        from app import app
        from models import db
        
        with app.app_context():
            # Parse the CSV with proper column mapping
            parser = parser_factory.get_parser(
                csv_file, 
                'firewall', 
                column_mapping=column_mapping
            )
            
            records = parser.parse()
            
            print(f"\nSuccessfully parsed {len(records)} records")
            
            # Clear existing records from observations.csv to avoid duplicates
            RawFirewallRule.query.filter_by(source_file='observations.csv').delete()
            db.session.commit()
            print("Cleared existing observations.csv records")
            
            # Store parsed records in database
            for i, record_data in enumerate(records):
                # Create rule_text from all fields for better normalization
                rule_text_parts = []
                for key, value in record_data.items():
                    if value and key not in ['id', 'created_at', 'updated_at']:
                        rule_text_parts.append(f"{key}: {value}")
                
                rule_text = "; ".join(rule_text_parts)
                
                raw_rule = RawFirewallRule(
                    source_file='observations.csv',
                    rule_name=record_data.get('rule_name'),  # Add rule_name from mapped field
                    rule_text=rule_text,
                    action=record_data.get('action'),        # Add action from mapped field
                    protocol=record_data.get('protocol'),
                    source=record_data.get('source'),        # Add source from mapped field
                    destination=record_data.get('destination'), # Add destination from mapped field
                    source_port=record_data.get('source_port'),
                    dest_port=record_data.get('dest_port'),
                    raw_text=json.dumps(record_data)  # Store all data as JSON in raw_text
                )
                
                db.session.add(raw_rule)
                
                if (i + 1) % 10 == 0:
                    print(f"Processed {i + 1} records...")
            
            db.session.commit()
            print(f"\nSuccessfully stored {len(records)} raw firewall rules")
            
            # Now normalize the rules
            print("\nNormalizing rules...")
            normalizer = RuleNormalizer()
            
            # Clear existing normalized rules from observations.csv
            from models import NormalizedRule
            NormalizedRule.query.filter_by(source_file='observations.csv').delete()
            db.session.commit()
            print("Cleared existing normalized rules for observations.csv")
            
            # Normalize each rule
            raw_rules = RawFirewallRule.query.filter_by(source_file='observations.csv').all()
            for i, raw_rule in enumerate(raw_rules):
                normalized_rules = normalizer.normalize_single_rule(raw_rule)
                for normalized_rule in normalized_rules:
                    db.session.add(normalized_rule)
                
                if (i + 1) % 10 == 0:
                    print(f"Normalized {i + 1} rules...")
            
            db.session.commit()
            print(f"Successfully normalized {len(raw_rules)} rules")
            
            # Verify the results
            print("\nVerifying results...")
            
            # Check raw rules
            raw_rules = RawFirewallRule.query.filter_by(source_file='observations.csv').all()
            print(f"Raw rules count: {len(raw_rules)}")
            
            # Check normalized rules
            normalized_rules = NormalizedRule.query.filter_by(source_file='observations.csv').all()
            print(f"Normalized rules count: {len(normalized_rules)}")
            
            # Show some examples
            print("\nFirst 5 normalized rules with port information:")
            for i, rule in enumerate(normalized_rules[:5]):
                print(f"Rule {i+1}:")
                print(f"  Rule Name: {rule.rule_name}")
                print(f"  Protocol: {rule.protocol}")
                print(f"  Source Port: {rule.source_port}")
                print(f"  Dest Port: {rule.dest_port}")
                print(f"  Service Name: {rule.service_name}")
                print()
    
    except Exception as e:
        print(f"Error processing observations.csv: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    process_observations_with_service()