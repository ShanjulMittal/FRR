#!/usr/bin/env python3
"""
Safe cleanup script to remove non-firewall rule records from the database.
This script handles foreign key constraints by deleting related records first.
"""

from models import db, RawFirewallRule, NormalizedRule, ReviewResult
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
    
    # Check related records
    normalized_count = NormalizedRule.query.count()
    review_results_count = ReviewResult.query.count()
    print(f"Normalized rules: {normalized_count}")
    print(f"Review results: {review_results_count}")
    
    # Breakdown by file
    print("\nBreakdown by source file:")
    file_counts = db.session.query(
        RawFirewallRule.source_file,
        func.count(RawFirewallRule.id).label('count')
    ).group_by(RawFirewallRule.source_file).all()
    
    for file_name, count in file_counts:
        print(f"  {file_name}: {count} records")
    
    return total_count, actual_rules, non_rules

def identify_records_to_delete():
    """Identify records that need to be deleted"""
    print(f"\nIdentifying records to delete...")
    
    # Records with empty or null raw_text, or null rule_type
    records_to_delete = RawFirewallRule.query.filter(
        db.or_(
            RawFirewallRule.raw_text.is_(None),
            RawFirewallRule.raw_text == '',
            RawFirewallRule.rule_type.is_(None)
        )
    ).all()
    
    print(f"Found {len(records_to_delete)} records to delete")
    
    # Group by source file
    file_groups = {}
    for record in records_to_delete:
        if record.source_file not in file_groups:
            file_groups[record.source_file] = []
        file_groups[record.source_file].append(record)
    
    print("Records to delete by file:")
    for file_name, records in file_groups.items():
        print(f"  {file_name}: {len(records)} records")
    
    return records_to_delete

def check_foreign_key_dependencies(record_ids):
    """Check what related records need to be deleted first"""
    print(f"\nChecking foreign key dependencies...")
    
    # Check normalized rules that reference these raw rules
    normalized_rules = NormalizedRule.query.filter(
        NormalizedRule.raw_rule_id.in_(record_ids)
    ).all()
    
    print(f"Found {len(normalized_rules)} normalized rules that reference these records")
    
    # Check review results that reference the normalized rules
    normalized_rule_ids = [nr.id for nr in normalized_rules]
    review_results = []
    if normalized_rule_ids:
        review_results = ReviewResult.query.filter(
            ReviewResult.normalized_rule_id.in_(normalized_rule_ids)
        ).all()
    
    print(f"Found {len(review_results)} review results that reference the normalized rules")
    
    return normalized_rules, review_results

def safe_cleanup_database():
    """Safely remove all non-firewall rule records and their dependencies"""
    print("\n=== SAFE CLEANUP PROCESS ===")
    
    # Get records to delete
    records_to_delete = identify_records_to_delete()
    
    if not records_to_delete:
        print("No non-firewall records found to delete.")
        return
    
    record_ids = [record.id for record in records_to_delete]
    
    # Check dependencies
    normalized_rules, review_results = check_foreign_key_dependencies(record_ids)
    
    print(f"\nCleanup plan:")
    print(f"  1. Delete {len(review_results)} review results")
    print(f"  2. Delete {len(normalized_rules)} normalized rules")
    print(f"  3. Delete {len(records_to_delete)} raw firewall rules")
    
    # Confirm deletion
    response = input(f"\nDo you want to proceed with this cleanup? (yes/no): ")
    if response.lower() != 'yes':
        print("Cleanup cancelled.")
        return
    
    try:
        # Step 1: Delete review results first
        if review_results:
            print(f"Deleting {len(review_results)} review results...")
            for result in review_results:
                db.session.delete(result)
            db.session.commit()
            print("✅ Review results deleted")
        
        # Step 2: Delete normalized rules
        if normalized_rules:
            print(f"Deleting {len(normalized_rules)} normalized rules...")
            for rule in normalized_rules:
                db.session.delete(rule)
            db.session.commit()
            print("✅ Normalized rules deleted")
        
        # Step 3: Delete raw firewall rules
        print(f"Deleting {len(records_to_delete)} raw firewall rules...")
        deleted_count = 0
        file_groups = {}
        
        for record in records_to_delete:
            if record.source_file not in file_groups:
                file_groups[record.source_file] = 0
            file_groups[record.source_file] += 1
            
            db.session.delete(record)
            deleted_count += 1
        
        db.session.commit()
        print(f"✅ Successfully deleted {deleted_count} non-firewall records")
        
        print("\nDeleted records by file:")
        for file_name, count in file_groups.items():
            print(f"  {file_name}: {count} records")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error during deletion: {e}")
        return
    
    print("\n=== POST-CLEANUP ANALYSIS ===")
    analyze_database()

def main():
    """Main execution function"""
    with app.app_context():
        print("🔍 Safe Firewall Rules Database Cleanup")
        print("=" * 50)
        
        # Analyze current state
        total_before, actual_before, non_rules_before = analyze_database()
        
        # Perform safe cleanup
        safe_cleanup_database()

if __name__ == "__main__":
    main()