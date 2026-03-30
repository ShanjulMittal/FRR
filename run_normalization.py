#!/usr/bin/env python3
"""
Script to run the rule normalization process on the newly uploaded data
"""

import os
import sys

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app import app, db
from models import RawFirewallRule, NormalizedRule
from rule_normalizer import RuleNormalizer

def run_normalization():
    """Run the rule normalization process"""
    
    with app.app_context():
        print("Starting rule normalization process...")
        
        # Check if there are raw rules to normalize
        raw_rules_count = RawFirewallRule.query.count()
        print(f"Found {raw_rules_count} raw firewall rules to normalize")
        
        if raw_rules_count == 0:
            print("No raw rules found to normalize")
            return False
        
        # Clear any existing normalized rules
        normalized_count = NormalizedRule.query.count()
        if normalized_count > 0:
            print(f"Clearing {normalized_count} existing normalized rules...")
            NormalizedRule.query.delete()
            db.session.commit()
        
        # Initialize the rule normalizer
        normalizer = RuleNormalizer()
        
        try:
            # Run normalization
            print("Running normalization process...")
            success = normalizer.normalize_all_rules()
            
            if success:
                normalized_count = NormalizedRule.query.count()
                print(f"✅ Normalization completed successfully! Created {normalized_count} normalized rules")
                
                # Show sample normalized rules with rule names
                normalized_rules = NormalizedRule.query.limit(5).all()
                if normalized_rules:
                    print("\nSample normalized rules:")
                    for rule in normalized_rules:
                        print(f"  - ID: {rule.id}, Rule Name: '{rule.rule_name}', Raw Rule ID: {rule.raw_rule_id}")
                
                return True
            else:
                print("❌ Normalization failed")
                return False
                
        except Exception as e:
            print(f"❌ Error during normalization: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = run_normalization()
    if success:
        print("\n🎉 Normalization process completed successfully!")
        print("The API endpoint /api/normalized-rules should now return data with proper rule names.")
    else:
        print("\n💥 Normalization process failed!")
    sys.exit(0 if success else 1)