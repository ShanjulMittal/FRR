#!/usr/bin/env python3
"""
Fix rule_name mapping for observations.csv
Map the rule_name to the original Rule Name values from the CSV
"""

import sqlite3
import sys
import os

# Mapping based on the original observations.csv data
RULE_NAME_MAPPING = {
    # Based on the original CSV: Observation ID -> Rule Name
    1: "WEB_ALLOW",
    2: "SSH_BLOCK", 
    3: "DNS_ALLOW",
    4: "SMTP_BLOCK",
    5: "RDP_ALLOW"
}

def get_observation_id_from_record(record):
    """
    Try to determine the original Observation ID from the record data
    by matching against the known patterns from observations.csv
    """
    source, dest, src_port, dst_port, protocol, action = record
    
    # Match against known patterns from the original CSV
    if source == "192.168.1.10" and dest == "10.0.0.5" and dst_port == "80":
        return 1  # WEB_ALLOW
    elif source == "10.0.0.100" and dest == "192.168.1.20" and dst_port == "22":
        return 2  # SSH_BLOCK
    elif source == "172.16.0.50" and dest == "8.8.8.8" and dst_port == "53":
        return 3  # DNS_ALLOW
    elif source == "192.168.1.15" and dest == "203.0.113.10" and dst_port == "25":
        return 4  # SMTP_BLOCK
    elif source == "10.0.0.200" and dest == "192.168.1.30" and dst_port == "3389":
        return 5  # RDP_ALLOW
    
    return None

def main():
    db_path = 'instance/firewall_review.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return 1
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Get all observations.csv records
        cursor.execute('''
            SELECT id, rule_name, source, destination, source_port, dest_port, protocol, action
            FROM raw_firewall_rules 
            WHERE source_file = 'observations.csv'
        ''')
        
        records = cursor.fetchall()
        print(f"Found {len(records)} records from observations.csv")
        
        updated_count = 0
        
        for record in records:
            record_id, current_rule_name, source, dest, src_port, dst_port, protocol, action = record
            
            # Try to match this record to an original observation
            obs_id = get_observation_id_from_record((source, dest, src_port, dst_port, protocol, action))
            
            if obs_id and obs_id in RULE_NAME_MAPPING:
                new_rule_name = RULE_NAME_MAPPING[obs_id]
                
                # Update the record
                cursor.execute('''
                    UPDATE raw_firewall_rules 
                    SET rule_name = ? 
                    WHERE id = ?
                ''', (new_rule_name, record_id))
                
                updated_count += 1
                print(f"Updated record {record_id}: '{current_rule_name}' -> '{new_rule_name}'")
            else:
                print(f"Could not match record {record_id} to original observation")
        
        # Commit changes
        conn.commit()
        print(f"\nSuccessfully updated {updated_count} records")
        
        # Show sample of updated records
        cursor.execute('''
            SELECT id, rule_name, action, source, destination 
            FROM raw_firewall_rules 
            WHERE source_file = 'observations.csv' 
            LIMIT 10
        ''')
        
        updated_records = cursor.fetchall()
        print("\nSample of updated records:")
        print("ID | Rule Name | Action | Source | Destination")
        print("-" * 80)
        for record in updated_records:
            print(f"{record[0]} | {record[1]} | {record[2]} | {record[3][:20]}... | {record[4][:20]}...")
        
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
        return 1
    
    finally:
        conn.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())