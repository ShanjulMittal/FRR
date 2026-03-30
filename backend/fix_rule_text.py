#!/usr/bin/env python3
"""
Fix rule_text field for all existing records.
This script will regenerate proper rule_text for all records.
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
    if record.source_port and record.source_port != '-':
        source_parts.append(f"port {record.source_port}")
    if source_parts:
        parts.append(f"from {' '.join(source_parts)}")
    
    # Add destination information
    dest_parts = []
    if record.destination:
        dest_parts.append(record.destination)
    if record.dest_port and record.dest_port != '-':
        dest_parts.append(f"port {record.dest_port}")
    if dest_parts:
        parts.append(f"to {' '.join(dest_parts)}")
    
    # Add ACL name if available
    if record.acl_name:
        parts.append(f"(ACL: {record.acl_name})")
    
    return ' '.join(parts) if parts else 'Firewall Rule'

def fix_rule_text():
    """Fix rule_text for all existing records"""
    with app.app_context():
        try:
            # Get all records
            all_records = RawFirewallRule.query.all()
            
            logger.info(f"Found {len(all_records)} records to update")
            
            updated_count = 0
            for record in all_records:
                # Generate proper rule_text from the record data
                generated_rule_text = _generate_rule_text_from_record(record)
                old_rule_text = record.rule_text
                record.rule_text = generated_rule_text
                updated_count += 1
                
                if updated_count <= 5:  # Show first 5 updates
                    logger.info(f"Record {record.id}: '{old_rule_text}' -> '{generated_rule_text}'")
                
                if updated_count % 20 == 0:
                    logger.info(f"Updated {updated_count} records...")
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Successfully updated {updated_count} records with proper rule_text")
            
        except Exception as e:
            logger.error(f"Error during migration: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    fix_rule_text()