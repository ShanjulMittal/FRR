#!/usr/bin/env python3
"""
Cleanup script to remove non-firewall rule records from the database.
This script removes CMDB data, VLAN data, and other enrichment data that
was incorrectly imported as firewall rules.
"""

from models import db, RawFirewallRule
from app import app
from sqlalchemy import func

def analyze_database():
    """Analyze current database state"""
    print("=== DATABASE ANALYSIS ===")
    
    # Total count
    total_count = RawFirewallRule.query.count()
    print(f"Total records: {total_count}")
    
    # Actual firewall rules (have rule_type and raw_text)
    actual_rules = RawFirewallRule.query.filter(
        RawFirewallRule.raw_text.isnot(None),
        RawFirewallRule.raw_text != '',
        RawFirewallRule.rule_type.isnot(None)
    ).count()
    print(f"Actual firewall rules: {actual_rules}")
    
    # Non-rule records
    non_rules = RawFirewallRule.query.filter(
        db.or_(
            RawFirewallRule.raw_text.is_(None),
            RawFirewallRule.raw_text == '',
            RawFirewallRule.rule_type.is_(None)
        )
    ).count()
    print(f"Non-firewall records: {non_rules}")
    
    # Breakdown by file
    print("\nBreakdown by source file:")
    file_counts = db.session.query(
        RawFirewallRule.source_file,
        func.count(RawFirewallRule.id).label('count')
    ).group_by(RawFirewallRule.source_file).all()
    
    for file_name, count in file_counts:
        print(f"  {file_name}: {count} records")
    
    return total_count, actual_rules, non_rules

def identify_non_firewall_files():
    """Identify files that contain non-firewall data"""
    non_firewall_files = [
        'cmdb_enrichment_data.csv',
        'vlan_enrichment_data.csv', 
        'valid_cmdb_assets.xlsx',
        'valid_firewall_rules.csv',  # CSV format but not actual rules
        'valid_firewall_rules.json'  # JSON format but not actual rules
    ]
    
    print(f"\nFiles identified as non-firewall data:")
    for file_name in non_firewall_files:
        count = RawFirewallRule.query.filter_by(source_file=file_name).count()
        if count > 0:
            print(f"  {file_name}: {count} records")
    
    return non_firewall_files

def identify_non_rule_records():
    """Identify records that don't have actual firewall rule content"""
    print(f"\nIdentifying records without firewall rule content...")
    
    # Records with empty or null raw_text, or null rule_type
    non_rule_records = RawFirewallRule.query.filter(
        db.or_(
            RawFirewallRule.raw_text.is_(None),
            RawFirewallRule.raw_text == '',
            RawFirewallRule.rule_type.is_(None)
        )
    ).all()
    
    print(f"Found {len(non_rule_records)} records without firewall rule content")
    
    # Group by source file
    file_groups = {}
    for record in non_rule_records:
        if record.source_file not in file_groups:
            file_groups[record.source_file] = []
        file_groups[record.source_file].append(record)
    
    print("Non-rule records by file:")
    for file_name, records in file_groups.items():
        print(f"  {file_name}: {len(records)} records")
        # Show sample record
        sample = records[0]
        print(f"    Sample - ID: {sample.id}, Rule Type: {sample.rule_type}, Raw Text: {sample.raw_text[:50] if sample.raw_text else 'None'}...")
    
    return non_rule_records

def cleanup_database():
    """Remove all non-firewall rule records"""
    print("\n=== CLEANUP PROCESS ===")
    
    # Get records to delete
    records_to_delete = RawFirewallRule.query.filter(
        db.or_(
            RawFirewallRule.raw_text.is_(None),
            RawFirewallRule.raw_text == '',
            RawFirewallRule.rule_type.is_(None)
        )
    ).all()
    
    if not records_to_delete:
        print("No non-firewall records found to delete.")
        return
    
    print(f"Preparing to delete {len(records_to_delete)} non-firewall records...")
    
    # Group by file for reporting
    file_groups = {}
    for record in records_to_delete:
        if record.source_file not in file_groups:
            file_groups[record.source_file] = 0
        file_groups[record.source_file] += 1
    
    print("Records to be deleted by file:")
    for file_name, count in file_groups.items():
        print(f"  {file_name}: {count} records")
    
    # Confirm deletion
    response = input(f"\nDo you want to delete these {len(records_to_delete)} non-firewall records? (yes/no): ")
    if response.lower() != 'yes':
        print("Cleanup cancelled.")
        return
    
    # Delete records
    deleted_count = 0
    for record in records_to_delete:
        db.session.delete(record)
        deleted_count += 1
    
    # Commit changes
    try:
        db.session.commit()
        print(f"✅ Successfully deleted {deleted_count} non-firewall records")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error during deletion: {e}")
        return
    
    print("\n=== POST-CLEANUP ANALYSIS ===")
    analyze_database()

def main():
    """Main execution function"""
    with app.app_context():
        print("🔍 Firewall Rules Database Cleanup")
        print("=" * 50)
        
        # Analyze current state
        total_before, actual_before, non_rules_before = analyze_database()
        
        # Identify problematic files
        identify_non_firewall_files()
        
        # Identify non-rule records
        identify_non_rule_records()
        
        # Perform cleanup
        cleanup_database()

if __name__ == "__main__":
    main()