#!/usr/bin/env python3
"""
Fix CMDB asset mappings to include missing target fields (hostname, description, pcidss_asset_category).
This script updates the __mapped_fields__ array and populates missing field data.
"""

import os
import sys
import json
import sqlite3
from datetime import datetime

def fix_cmdb_mappings():
    """Fix CMDB asset mappings to include missing target fields."""
    
    db_path = "/Users/shanjulmittal/FRR/backend/firewall_review.db"
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all CMDB assets
        cursor.execute("SELECT id, hostname, additional_data FROM cmdb_assets")
        assets = cursor.fetchall()
        
        fixed_count = 0
        
        for asset in assets:
            asset_id = asset['id']
            hostname = asset['hostname']
            additional_data_str = asset['additional_data']
            
            # Parse additional_data
            additional_data = {}
            if additional_data_str:
                try:
                    additional_data = json.loads(additional_data_str)
                except json.JSONDecodeError:
                    print(f"Warning: Invalid JSON in additional_data for asset {asset_id}")
                    additional_data = {}
            
            # Get current mapped fields
            current_mapped_fields = additional_data.get('__mapped_fields__', [])
            
            # Target fields to ensure are mapped
            target_fields = ['hostname', 'description', 'pcidss_asset_category']
            
            # Check which target fields need to be added
            missing_fields = [field for field in target_fields if field not in current_mapped_fields]
            
            if missing_fields:
                # Add missing fields to mapped fields
                updated_mapped_fields = current_mapped_fields + missing_fields
                additional_data['__mapped_fields__'] = updated_mapped_fields
                
                # Try to populate missing data where possible
                if 'hostname' in missing_fields and hostname:
                    # hostname is already in the base model, no need to add to additional_data
                    pass
                
                if 'description' in missing_fields and 'description' not in additional_data:
                    # Try to generate a description from other fields
                    description_parts = []
                    if hostname:
                        description_parts.append(f"Device: {hostname}")
                    if additional_data.get('asset_type'):
                        description_parts.append(f"Type: {additional_data.get('asset_type')}")
                    if additional_data.get('application_name'):
                        description_parts.append(f"Application: {additional_data.get('application_name')}")
                    
                    if description_parts:
                        additional_data['description'] = " | ".join(description_parts)
                
                if 'pcidss_asset_category' in missing_fields and 'pcidss_asset_category' not in additional_data:
                    # Set a default PCI DSS category if not present
                    additional_data['pcidss_asset_category'] = 'C'  # Default to 'No cardholder data'
                
                # Update the asset
                updated_additional_data = json.dumps(additional_data)
                cursor.execute(
                    "UPDATE cmdb_assets SET additional_data = ?, updated_at = ? WHERE id = ?",
                    (updated_additional_data, datetime.now(), asset_id)
                )
                
                print(f"Fixed asset {asset_id}: Added {missing_fields} to mapped fields")
                fixed_count += 1
        
        conn.commit()
        print(f"\nSuccessfully fixed {fixed_count} CMDB assets")
        
        # Show summary of what fields are now mapped
        cursor.execute("""
            SELECT COUNT(*) as total,
                   COUNT(CASE WHEN additional_data LIKE '%\"hostname\"%' THEN 1 END) as hostname_mapped,
                   COUNT(CASE WHEN additional_data LIKE '%\"description\"%' THEN 1 END) as description_mapped,
                   COUNT(CASE WHEN additional_data LIKE '%\"pcidss_asset_category\"%' THEN 1 END) as pci_mapped
            FROM cmdb_assets
        """)
        summary = cursor.fetchone()
        
        print(f"\nSummary after fix:")
        print(f"Total assets: {summary['total']}")
        print(f"Assets with hostname mapped: {summary['hostname_mapped']}")
        print(f"Assets with description mapped: {summary['description_mapped']}")
        print(f"Assets with PCI DSS category mapped: {summary['pci_mapped']}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error fixing CMDB mappings: {str(e)}")
        return False

if __name__ == "__main__":
    print("Starting CMDB mapping fix...")
    success = fix_cmdb_mappings()
    sys.exit(0 if success else 1)