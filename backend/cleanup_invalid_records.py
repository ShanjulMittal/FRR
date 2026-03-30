#!/usr/bin/env python3
"""
Database cleanup script to remove invalid records from observations.xlsx
These records have empty raw_text and no meaningful firewall rule data
"""

from app import app, db
from models import RawFirewallRule

def cleanup_invalid_records():
    """Remove invalid records from observations.xlsx"""
    with app.app_context():
        try:
            # First, let's see what we're dealing with
            print("Analyzing observations.xlsx records...")
            obs_records = RawFirewallRule.query.filter_by(source_file='observations.xlsx').all()
            print(f"Found {len(obs_records)} records from observations.xlsx")
            
            # Check if they're all invalid (empty raw_text and no meaningful data)
            invalid_count = 0
            valid_count = 0
            
            for record in obs_records:
                # Consider a record invalid if it has empty/null raw_text and no meaningful firewall data
                is_invalid = (
                    (not record.raw_text or record.raw_text.strip() == '') and
                    not record.action and
                    not record.protocol and
                    not record.source and
                    not record.destination and
                    not record.source_port and
                    not record.dest_port
                )
                
                if is_invalid:
                    invalid_count += 1
                else:
                    valid_count += 1
            
            print(f"Invalid records: {invalid_count}")
            print(f"Valid records: {valid_count}")
            
            if invalid_count > 0:
                # Ask for confirmation before deletion
                response = input(f"\nDo you want to delete {invalid_count} invalid records from observations.xlsx? (y/N): ")
                
                if response.lower() in ['y', 'yes']:
                    # Delete invalid records
                    deleted_count = 0
                    for record in obs_records:
                        is_invalid = (
                            (not record.raw_text or record.raw_text.strip() == '') and
                            not record.action and
                            not record.protocol and
                            not record.source and
                            not record.destination and
                            not record.source_port and
                            not record.dest_port
                        )
                        
                        if is_invalid:
                            db.session.delete(record)
                            deleted_count += 1
                    
                    # Commit the changes
                    db.session.commit()
                    print(f"\nSuccessfully deleted {deleted_count} invalid records!")
                    
                    # Show the new total count
                    new_total = RawFirewallRule.query.count()
                    print(f"New total firewall rules count: {new_total}")
                    
                else:
                    print("Cleanup cancelled.")
            else:
                print("No invalid records found to clean up.")
                
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")
            db.session.rollback()
            raise

def show_current_stats():
    """Show current database statistics"""
    with app.app_context():
        try:
            total_count = RawFirewallRule.query.count()
            print(f"Current total firewall rules: {total_count}")
            
            # Show breakdown by source file
            print("\nBreakdown by source file:")
            files = db.session.query(RawFirewallRule.source_file).distinct().all()
            for file_tuple in files:
                file_name = file_tuple[0]
                file_count = RawFirewallRule.query.filter_by(source_file=file_name).count()
                print(f"  {file_name}: {file_count} rules")
                
        except Exception as e:
            print(f"Error getting stats: {str(e)}")

if __name__ == '__main__':
    print("=== Database Cleanup Tool ===")
    print("This tool will help clean up invalid records from observations.xlsx")
    print()
    
    # Show current stats
    show_current_stats()
    print()
    
    # Run cleanup
    cleanup_invalid_records()
    print()
    
    # Show final stats
    print("=== Final Statistics ===")
    show_current_stats()