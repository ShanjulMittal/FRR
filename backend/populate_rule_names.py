#!/usr/bin/env python3
"""
Populate rule_name field for all raw firewall rules based on their content.
This script generates meaningful rule names from the rule's action, protocol, source, and destination.
"""

import sqlite3
import os
import re

def generate_rule_name(rule_data):
    """Generate a meaningful rule name based on rule content"""
    action = (rule_data.get('action') or '').upper()
    protocol = (rule_data.get('protocol') or '').upper()
    source = rule_data.get('source') or ''
    destination = rule_data.get('destination') or ''
    dest_port = rule_data.get('dest_port') or ''
    
    # Clean up source and destination for rule naming
    def clean_address(addr):
        if not addr or addr in ['any', 'ANY', '0.0.0.0/0', '0.0.0.0', 'host']:
            return 'ANY'
        # Extract meaningful parts from complex addresses
        if '/' in addr:  # CIDR notation
            return addr.split('/')[0].replace('.', '_')
        if 'host' in addr:
            return addr.replace('host ', '').replace('.', '_')
        # For object groups or named entities
        if not re.match(r'^\d+\.\d+\.\d+\.\d+', addr):
            return addr.upper().replace('-', '_').replace(' ', '_')
        return addr.replace('.', '_')
    
    source_clean = clean_address(source)
    dest_clean = clean_address(destination)
    
    # Generate rule name components
    components = []
    
    # Add action
    if action in ['PERMIT', 'ALLOW', 'ACCEPT']:
        components.append('ALLOW')
    elif action in ['DENY', 'DROP', 'REJECT']:
        components.append('BLOCK')
    else:
        components.append(action or 'RULE')
    
    # Add protocol if specific
    if protocol and protocol not in ['IP', 'ANY']:
        components.append(protocol)
    
    # Add service/port information
    if dest_port and dest_port not in ['any', 'ANY', '0']:
        if dest_port == '80':
            components.append('HTTP')
        elif dest_port == '443':
            components.append('HTTPS')
        elif dest_port == '22':
            components.append('SSH')
        elif dest_port == '21':
            components.append('FTP')
        elif dest_port == '25':
            components.append('SMTP')
        elif dest_port == '53':
            components.append('DNS')
        elif dest_port == '3389':
            components.append('RDP')
        else:
            components.append(f'PORT_{dest_port}')
    
    # Add source info if not ANY
    if source_clean != 'ANY' and len(source_clean) < 20:
        components.append(f'FROM_{source_clean}')
    
    # Add destination info if not ANY
    if dest_clean != 'ANY' and len(dest_clean) < 20:
        components.append(f'TO_{dest_clean}')
    
    # Join components and limit length
    rule_name = '_'.join(components)
    if len(rule_name) > 80:
        rule_name = rule_name[:77] + '...'
    
    return rule_name

def main():
    db_path = 'instance/firewall_review.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return 1
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("Populating rule names for all raw firewall rules...")
        
        # Get all raw firewall rules that don't have rule names
        cursor.execute('''
            SELECT id, action, protocol, source, destination, dest_port, raw_text
            FROM raw_firewall_rules 
            WHERE rule_name IS NULL OR rule_name = 'None' OR rule_name = ''
            ORDER BY id
        ''')
        
        records = cursor.fetchall()
        print(f"Found {len(records)} records to update")
        
        updated_count = 0
        for record in records:
            record_id, action, protocol, source, destination, dest_port, raw_text = record
            
            rule_data = {
                'action': action,
                'protocol': protocol,
                'source': source,
                'destination': destination,
                'dest_port': dest_port
            }
            
            rule_name = generate_rule_name(rule_data)
            
            # Update the record
            cursor.execute('''
                UPDATE raw_firewall_rules 
                SET rule_name = ?
                WHERE id = ?
            ''', (rule_name, record_id))
            
            updated_count += 1
            if updated_count % 10 == 0:
                print(f"Updated {updated_count} records...")
        
        conn.commit()
        print(f"✓ Successfully updated {updated_count} records")
        
        # Show sample of updated records
        print("\nSample of updated records:")
        cursor.execute('''
            SELECT id, rule_name, action, protocol, source, destination, dest_port
            FROM raw_firewall_rules 
            WHERE rule_name IS NOT NULL AND rule_name != 'None'
            ORDER BY id
            LIMIT 5
        ''')
        
        samples = cursor.fetchall()
        print("ID | Rule Name | Action | Protocol | Source | Destination | Dest Port")
        print("-" * 100)
        for sample in samples:
            print(f"{sample[0]} | {sample[1]} | {sample[2]} | {sample[3]} | {sample[4]} | {sample[5]} | {sample[6]}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
        return 1
    
    finally:
        conn.close()

if __name__ == "__main__":
    exit(main())