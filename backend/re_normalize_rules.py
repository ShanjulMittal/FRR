#!/usr/bin/env python3
"""
Re-normalize existing rules to populate the new source_ip_with_zone and dest_ip_with_zone fields
"""

import os
import sys
import logging
from models import db, NormalizedRule, RawFirewallRule
from rule_normalizer import RuleNormalizer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def re_normalize_all_rules():
    """Re-normalize all existing rules to populate new fields"""
    try:
        logger.info("Starting re-normalization process...")
        
        # Get all normalized rules
        normalized_rules = NormalizedRule.query.all()
        total_rules = len(normalized_rules)
        logger.info(f"Found {total_rules} normalized rules to re-normalize")
        
        updated_count = 0
        error_count = 0
        
        for rule in normalized_rules:
            try:
                # Get the corresponding raw rule
                raw_rule = RawFirewallRule.query.get(rule.raw_rule_id)
                if not raw_rule:
                    logger.warning(f"No raw rule found for normalized rule {rule.id}")
                    continue
                
                # Create a normalizer instance
                normalizer = RuleNormalizer()
                
                # Format the source and destination with zone information
                source_ip_with_zone = normalizer.format_source_with_zone(
                    rule.source_ip or '', 
                    rule.source_zone
                )
                
                dest_ip_with_zone = normalizer.format_destination_with_zone(
                    rule.dest_ip or '', 
                    rule.dest_zone
                )
                
                # Update the rule with the new fields
                rule.source_ip_with_zone = source_ip_with_zone
                rule.dest_ip_with_zone = dest_ip_with_zone
                
                db.session.add(rule)
                updated_count += 1
                
                # Commit every 100 rules to avoid memory issues
                if updated_count % 100 == 0:
                    db.session.commit()
                    logger.info(f"Updated {updated_count} rules...")
                
            except Exception as e:
                logger.error(f"Error re-normalizing rule {rule.id}: {str(e)}")
                error_count += 1
                db.session.rollback()
                continue
        
        # Final commit
        db.session.commit()
        
        logger.info(f"Re-normalization complete. Updated: {updated_count}, Errors: {error_count}")
        return True
        
    except Exception as e:
        logger.error(f"Re-normalization failed: {str(e)}")
        db.session.rollback()
        return False

if __name__ == '__main__':
    # Add the backend directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Import Flask app
    from app import app
    
    # Run with app context
    with app.app_context():
        success = re_normalize_all_rules()
        sys.exit(0 if success else 1)