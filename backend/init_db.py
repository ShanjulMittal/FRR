#!/usr/bin/env python3
"""
Database initialization script for Firewall Rule Review Application
Creates all database tables and sets up initial schema
"""

from app import app, db
from models import (RawFirewallRule, CMDBAsset, VLANNetwork, ObjectGroup, 
                   UploadHistory, NormalizedRule, ComplianceRule, 
                   ReviewProfile, ProfileRuleLink, ServicePortMapping)

def init_database():
    """Initialize the database with all tables"""
    with app.app_context():
        try:
            # Drop all existing tables (for development)
            print("Dropping existing tables...")
            db.drop_all()
            
            # Create all tables
            print("Creating database tables...")
            db.create_all()
            
            print("Database initialization completed successfully!")
            print("\nCreated tables:")
            print("- raw_firewall_rules")
            print("- cmdb_assets")
            print("- vlan_networks")
            print("- object_groups")
            print("- object_group_members")
            print("- normalized_rules")
            print("- upload_history")
            print("- compliance_rules")
            print("- review_profiles")
            print("- profile_rule_link")
            print("- service_port_mappings")
            
        except Exception as e:
            print(f"Error initializing database: {str(e)}")
            raise

if __name__ == '__main__':
    init_database()