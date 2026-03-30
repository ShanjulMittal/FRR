#!/usr/bin/env python3
"""
Enhance observations.csv data by:
1. Adding a rule_name field to store the "Rule Name" column
2. Updating rule_text to contain complete rule information with all columns
"""

import sqlite3
import csv
import os

def main():
    db_path = 'instance/firewall_review.db'
    csv_path = '/Users/shanjulmittal/FRR/test-files/observations.csv'
    
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return 1
    
    if not os.path.exists(csv_path):
        print(f"CSV file not found: {csv_path}")
        return 1
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Step 1: Add rule_name column if it doesn't exist
        print("Step 1: Adding rule_name column...")
        try:
            cursor.execute('ALTER TABLE raw_firewall_rules ADD COLUMN rule_name VARCHAR(100)')
            print("✓ Added rule_name column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("✓ rule_name column already exists")
            else:
                raise e
        
        # Step 2: Read the original CSV to get the mapping
        print("Step 2: Reading original CSV data...")
        csv_data = {}
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                obs_id = row['Observation ID']
                csv_data[obs_id] = {
                    'rule_name': row['Rule Name'],
                    'source': row['Source'],
                    'destination': row['Destination'],
                    'src_port': row['Src Port'],
                    'dst_port': row['Dst Port'],
                    'protocol': row['Proto'],
                    'decision': row['Decision'],
                    'line': row['Line'],
                    'type': row['Type']
                }
        
        print(f"✓ Read {len(csv_data)} records from CSV")
        
        # Step 3: Update existing observations.csv records
        print("Step 3: Updating existing records...")
        
        # Get current observations.csv records
        cursor.execute('''
            SELECT id, rule_text, source, destination, source_port, dest_port, protocol, action
            FROM raw_firewall_rules 
            WHERE source_file = 'observations.csv'
            ORDER BY id
        ''')
        
        records = cursor.fetchall()
        print(f"Found {len(records)} existing records to update")
        
        updated_count = 0
        for i, record in enumerate(records, 1):
            record_id, current_rule_text, source, destination, source_port, dest_port, protocol, action = record
            
            # Try to match with CSV data based on position or content
            obs_id = str(i)  # Assuming records are in order
            
            if obs_id in csv_data:
                csv_row = csv_data[obs_id]
                rule_name = csv_row['rule_name']
                
                # Create comprehensive rule_text with all information
                rule_text_parts = []
                rule_text_parts.append(f"Rule: {rule_name}")
                rule_text_parts.append(f"Action: {action or csv_row['decision']}")
                rule_text_parts.append(f"Protocol: {protocol or csv_row['protocol']}")
                rule_text_parts.append(f"Source: {source or csv_row['source']}")
                rule_text_parts.append(f"Destination: {destination or csv_row['destination']}")
                
                if source_port and source_port != '-':
                    rule_text_parts.append(f"Source Port: {source_port}")
                elif csv_row['src_port'] and csv_row['src_port'] != '-':
                    rule_text_parts.append(f"Source Port: {csv_row['src_port']}")
                
                if dest_port and dest_port != '-':
                    rule_text_parts.append(f"Dest Port: {dest_port}")
                elif csv_row['dst_port'] and csv_row['dst_port'] != '-':
                    rule_text_parts.append(f"Dest Port: {csv_row['dst_port']}")
                
                rule_text_parts.append(f"Line: {csv_row['line']}")
                rule_text_parts.append(f"Type: {csv_row['type']}")
                
                complete_rule_text = " | ".join(rule_text_parts)
                
                # Update the record
                cursor.execute('''
                    UPDATE raw_firewall_rules 
                    SET rule_name = ?, rule_text = ?
                    WHERE id = ?
                ''', (rule_name, complete_rule_text, record_id))
                
                updated_count += 1
                print(f"✓ Updated record {record_id}: {rule_name}")
        
        conn.commit()
        print(f"✓ Successfully updated {updated_count} records")
        
        # Step 4: Show sample of updated records
        print("\nStep 4: Sample of updated records:")
        cursor.execute('''
            SELECT id, rule_name, rule_text, action, source, destination
            FROM raw_firewall_rules 
            WHERE source_file = 'observations.csv'
            ORDER BY id
            LIMIT 3
        ''')
        
        samples = cursor.fetchall()
        print("ID | Rule Name | Rule Text | Action | Source | Destination")
        print("-" * 120)
        for sample in samples:
            rule_text_preview = sample[2][:60] + "..." if len(sample[2]) > 60 else sample[2]
            print(f"{sample[0]} | {sample[1]} | {rule_text_preview} | {sample[3]} | {sample[4]} | {sample[5]}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
        return 1
    
    finally:
        conn.close()

if __name__ == "__main__":
    exit(main())