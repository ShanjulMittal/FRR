#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = '/Users/shanjulmittal/FRR/backend/firewall_review.db'

def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    return column in cols

def add_column(cursor, table, column_def):
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")

def main():
    if not os.path.exists(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        return 1
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        print("Applying firewall fields migration...")
        # RawFirewallRule additions
        if not column_exists(cur, 'raw_firewall_rules', 'source_zone'):
            add_column(cur, 'raw_firewall_rules', 'source_zone VARCHAR(100)')
            print("Added raw_firewall_rules.source_zone")
        if not column_exists(cur, 'raw_firewall_rules', 'dest_zone'):
            add_column(cur, 'raw_firewall_rules', 'dest_zone VARCHAR(100)')
            print("Added raw_firewall_rules.dest_zone")
        if not column_exists(cur, 'raw_firewall_rules', 'application'):
            add_column(cur, 'raw_firewall_rules', 'application VARCHAR(100)')
            print("Added raw_firewall_rules.application")

        # NormalizedRule additions
        if not column_exists(cur, 'normalized_rules', 'source_zone'):
            add_column(cur, 'normalized_rules', 'source_zone VARCHAR(100)')
            print("Added normalized_rules.source_zone")
        if not column_exists(cur, 'normalized_rules', 'dest_zone'):
            add_column(cur, 'normalized_rules', 'dest_zone VARCHAR(100)')
            print("Added normalized_rules.dest_zone")
        if not column_exists(cur, 'normalized_rules', 'application'):
            add_column(cur, 'normalized_rules', 'application VARCHAR(100)')
            print("Added normalized_rules.application")

        conn.commit()
        print("Migration complete.")
        return 0
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
        return 1
    finally:
        conn.close()

if __name__ == '__main__':
    exit(main())