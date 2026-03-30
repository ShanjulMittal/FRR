#!/usr/bin/env python3
"""
Migration script to add rule_text field and populate it for existing records.
This script will:
1. Add the rule_text column to the database (if not already added)
2. Populate rule_text for existing records where it's empty
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, RawFirewallRule
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _generate_rule_text_from_record(record):
    """Generate rule text from a RawFirewallRule record"""
    parts = []
    
    # Add action if available
    if record.action:
        parts.append(record.action)
    
    # Add protocol if available
    if record.protocol:
        parts.append(record.protocol)
    
    # Add source information
    source_parts = []
    if record.source:
        source_parts.append(record.source)
    if record.source_port:
        source_parts.append(f"port {record.source_port}")
    if source_parts:
        parts.append(f"from {' '.join(source_parts)}")
    
    # Add destination information
    dest_parts = []
    if record.destination:
        dest_parts.append(record.destination)
    if record.dest_port:
        dest_parts.append(f"port {record.dest_port}")
    if dest_parts:
        parts.append(f"to {' '.join(dest_parts)}")
    
    # Add ACL name if available
    if record.acl_name:
        parts.append(f"(ACL: {record.acl_name})")
    
    return ' '.join(parts) if parts else 'Firewall Rule'

def migrate_rule_text():
    """Migrate existing records to populate rule_text field"""
    with app.app_context():
        try:
            # Get all records where rule_text is None or empty
            records_to_update = RawFirewallRule.query.filter(
                db.or_(
                    RawFirewallRule.rule_text.is_(None),
                    RawFirewallRule.rule_text == ''
                )
            ).all()
            
            logger.info(f"Found {len(records_to_update)} records to update")
            
            updated_count = 0
            for record in records_to_update:
                # Generate rule_text from the record data
                generated_rule_text = _generate_rule_text_from_record(record)
                record.rule_text = generated_rule_text
                updated_count += 1
                
                if updated_count % 100 == 0:
                    logger.info(f"Updated {updated_count} records...")
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Successfully updated {updated_count} records with rule_text")
            
            # Verify the migration
            total_records = RawFirewallRule.query.count()
            records_with_rule_text = RawFirewallRule.query.filter(
                RawFirewallRule.rule_text.isnot(None),
                RawFirewallRule.rule_text != ''
            ).count()
            
            logger.info(f"Migration complete: {records_with_rule_text}/{total_records} records have rule_text")
            
        except Exception as e:
            logger.error(f"Error during migration: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    migrate_rule_text()