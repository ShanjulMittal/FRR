#!/usr/bin/env python3
"""
Migration script to add rule_name column to NormalizedRule table
"""

from app import app, db
from models import NormalizedRule
from sqlalchemy import text

def add_rule_name_column():
    """Add rule_name column to normalized_rule table"""
    with app.app_context():
        try:
            # Check if column already exists (SQLite specific)
            with db.engine.connect() as connection:
                result = connection.execute(text("""
                    PRAGMA table_info(normalized_rule)
                """))
                
                columns = [row[1] for row in result.fetchall()]  # row[1] is column name
                
                if 'rule_name' in columns:
                    print("Column 'rule_name' already exists in normalized_rule table")
                    return
                
                # Add the column (SQLite specific)
                connection.execute(text("""
                    ALTER TABLE normalized_rule 
                    ADD COLUMN rule_name VARCHAR(100)
                """))
                
                connection.commit()
            
            print("Successfully added rule_name column to normalized_rule table")
            
        except Exception as e:
            print(f"Error adding rule_name column: {str(e)}")
            raise

if __name__ == "__main__":
    add_rule_name_column()