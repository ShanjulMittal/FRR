#!/usr/bin/env python3
"""
Check normalized rules and verify rule_text field
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, NormalizedRule, RawFirewallRule
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_normalized_rules():
    """Check normalized rules and rule_text field"""
    with app.app_context():
        try:
            # Count normalized rules
            total_normalized = db.session.query(NormalizedRule).count()
            logger.info(f"Total normalized rules: {total_normalized}")
            
            if total_normalized == 0:
                logger.info("No normalized rules found. Let's check raw rules with rule_text:")
                
                # Check raw rules with rule_text
                raw_with_rule_text = db.session.query(RawFirewallRule).filter(
                    RawFirewallRule.rule_text.isnot(None),
                    RawFirewallRule.rule_text != ''
                ).count()
                
                logger.info(f"Raw rules with rule_text: {raw_with_rule_text}")
                
                # Show sample raw rule
                sample_raw = db.session.query(RawFirewallRule).filter(
                    RawFirewallRule.rule_text.isnot(None),
                    RawFirewallRule.rule_text != ''
                ).first()
                
                if sample_raw:
                    logger.info(f"Sample raw rule:")
                    logger.info(f"  ID: {sample_raw.id}")
                    logger.info(f"  Rule Text: {sample_raw.rule_text[:100]}...")
                    logger.info(f"  Raw Text: {sample_raw.raw_text[:100]}...")
                
                return
            
            # Check first few normalized rules
            sample_rules = db.session.query(NormalizedRule).limit(3).all()
            
            for rule in sample_rules:
                logger.info(f"Normalized Rule ID: {rule.id}")
                rule_dict = rule.to_dict()
                
                has_rule_text = 'rule_text' in rule_dict
                has_raw_text = 'raw_text' in rule_dict
                
                logger.info(f"  Has rule_text: {has_rule_text}")
                logger.info(f"  Has raw_text: {has_raw_text}")
                
                if has_rule_text:
                    logger.info(f"  Rule Text: {rule_dict['rule_text'][:100]}...")
                if has_raw_text:
                    logger.info(f"  Raw Text: {rule_dict['raw_text'][:100]}...")
                
                logger.info("-" * 40)
            
        except Exception as e:
            logger.error(f"Error checking rules: {str(e)}")
            raise

if __name__ == "__main__":
    check_normalized_rules()