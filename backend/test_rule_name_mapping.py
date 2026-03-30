import sys
import os
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from models import db, RawFirewallRule, NormalizedRule
from parsers.parser_factory import parser_factory
from rule_normalizer import RuleNormalizer
from flask import Flask

# Initialize Flask app and database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/shanjulmittal/FRR/backend/firewall_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def _generate_rule_text_from_csv(record):
    """Generate comprehensive rule text from CSV record fields to capture entire raw detail"""
    parts = []
    
    # Add all available fields to create comprehensive rule text
    for key, value in record.items():
        if value and str(value).strip():
            parts.append(f"{key}: {value}")
    
    return " | ".join(parts) if parts else "No rule text available"

def store_parsed_data(parsed_data, file_type, source_file):
    """Store parsed data in appropriate database tables (simplified version for testing)"""
    
    records_processed = 0
    
    try:
        if file_type == 'firewall':
            # Clear existing raw firewall rules for this source file to prevent duplicates
            existing_count = db.session.query(RawFirewallRule).filter_by(source_file=source_file).count()
            if existing_count > 0:
                db.session.query(RawFirewallRule).filter_by(source_file=source_file).delete()
                db.session.commit()
                print(f"Cleared {existing_count} existing raw firewall rules for {source_file}")
            
            for record in parsed_data:
                # Auto-map rule_text to contain the entire raw detail of the imported file for this specific rule
                raw_text = record.get('raw_text', '')
                rule_text = raw_text if raw_text else _generate_rule_text_from_csv(record)
                
                firewall_rule = RawFirewallRule(
                    source_file=source_file,
                    file_line_number=record.get('line_number'),
                    rule_type=record.get('rule_type'),
                    vendor=record.get('vendor'),
                    acl_name=record.get('acl_name'),
                    rule_name=record.get('rule_name'),  # Add the rule_name field
                    action=record.get('action'),  # Use mapped action field
                    protocol=record.get('protocol'),
                    source=record.get('source'),  # Use mapped source field
                    destination=record.get('destination'),  # Use mapped destination field
                    source_port=record.get('source_port') or record.get('port'),  # Try both source_port and port
                    dest_port=record.get('dest_port') or record.get('port'),  # Try both dest_port and port
                    inside_interface=record.get('inside_interface'),
                    outside_interface=record.get('outside_interface'),
                    real_source=record.get('real_source'),
                    mapped_source=record.get('mapped_source'),
                    real_destination=record.get('real_destination'),
                    mapped_destination=record.get('mapped_destination'),
                    raw_text=raw_text,  # Complete original rule text from file
                    rule_text=rule_text  # Auto-mapped to contain entire raw detail for this specific rule
                )
                db.session.add(firewall_rule)
                records_processed += 1
        
        db.session.commit()
        return records_processed
        
    except Exception as e:
        db.session.rollback()
        raise e

def test_rule_name_mapping():
    with app.app_context():
        print("Testing rule name mapping functionality...")
        
        # Clear existing data
        print("Clearing existing data...")
        NormalizedRule.query.delete()
        RawFirewallRule.query.delete()
        db.session.commit()
        
        # Parse CSV file
        csv_file_path = '/Users/shanjulmittal/FRR/test-files/observations.csv'
        print(f"Parsing CSV file: {csv_file_path}")
        
        # Use parser factory to parse the file
        parsed_data = parser_factory.parse_file(csv_file_path, 'firewall')
        print(f"Parsed {len(parsed_data)} records")
        
        # Store parsed data
        print("Storing parsed data...")
        records_processed = store_parsed_data(parsed_data, 'firewall', 'observations.csv')
        print(f"Stored {records_processed} raw firewall rules")
        
        # Check rule_name in raw rules
        print("\nChecking rule_name in raw rules...")
        raw_rules_with_names = RawFirewallRule.query.filter(RawFirewallRule.rule_name.isnot(None)).all()
        print(f"Raw rules with rule_name: {len(raw_rules_with_names)}")
        
        if raw_rules_with_names:
            print("Sample rule names from raw rules:")
            for rule in raw_rules_with_names[:5]:  # Show first 5
                print(f"  - ID: {rule.id}, Rule Name: '{rule.rule_name}'")
        
        # Normalize rules
        print("\nNormalizing rules...")
        normalizer = RuleNormalizer()
        result = normalizer.normalize_all_rules(source_file='observations.csv', clear_existing=True)
        
        if result.get('success'):
            print(f"Normalization successful: {result.get('message')}")
            stats = result.get('stats', {})
            print(f"Stats: {stats}")
        else:
            print(f"Normalization failed: {result.get('message')}")
            return
        
        # Check rule_name in normalized rules
        print("\nChecking rule_name in normalized rules...")
        normalized_rules_with_names = NormalizedRule.query.filter(NormalizedRule.rule_name.isnot(None)).all()
        print(f"Normalized rules with rule_name: {len(normalized_rules_with_names)}")
        
        if normalized_rules_with_names:
            print("Sample rule names from normalized rules:")
            for rule in normalized_rules_with_names[:5]:  # Show first 5
                print(f"  - ID: {rule.id}, Rule Name: '{rule.rule_name}'")
        
        # Summary
        total_raw = RawFirewallRule.query.count()
        total_normalized = NormalizedRule.query.count()
        raw_with_names = RawFirewallRule.query.filter(RawFirewallRule.rule_name.isnot(None)).count()
        normalized_with_names = NormalizedRule.query.filter(NormalizedRule.rule_name.isnot(None)).count()
        
        print(f"\n=== SUMMARY ===")
        print(f"Total raw rules: {total_raw}")
        print(f"Raw rules with rule_name: {raw_with_names}")
        print(f"Total normalized rules: {total_normalized}")
        print(f"Normalized rules with rule_name: {normalized_with_names}")
        
        if raw_with_names > 0 and normalized_with_names > 0:
            print("✅ SUCCESS: Rule names are being mapped from raw to normalized rules!")
        elif raw_with_names > 0 and normalized_with_names == 0:
            print("❌ ISSUE: Rule names exist in raw rules but not in normalized rules")
        elif raw_with_names == 0:
            print("❌ ISSUE: No rule names found in raw rules - check CSV parsing")
        else:
            print("❓ UNKNOWN: Unexpected state")

if __name__ == "__main__":
    test_rule_name_mapping()