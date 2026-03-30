#!/usr/bin/env python3
"""
Script to add rule_text column to existing database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_rule_text_column():
    """Add rule_text column to raw_firewall_rules table"""
    with app.app_context():
        try:
            # Check if column already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text("PRAGMA table_info(raw_firewall_rules)"))
                columns = [row[1] for row in result]
                
                if 'rule_text' in columns:
                    logger.info("rule_text column already exists")
                    return
                
                # Add the column
                conn.execute(db.text("ALTER TABLE raw_firewall_rules ADD COLUMN rule_text TEXT"))
                conn.commit()
                logger.info("Successfully added rule_text column to raw_firewall_rules table")
            
        except Exception as e:
            logger.error(f"Error adding column: {str(e)}")
            raise

if __name__ == "__main__":
    add_rule_text_column()