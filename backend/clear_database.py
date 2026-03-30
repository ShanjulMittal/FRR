#!/usr/bin/env python3
"""
Clear all data from the database for fresh testing
"""

from models import db, RawFirewallRule, NormalizedRule, CMDBAsset, VLANNetwork, ObjectGroup, ObjectGroupMember
from app import app

def clear_database():
    """Clear all data from the database"""
    with app.app_context():
        try:
            # Get counts before deletion
            raw_count = RawFirewallRule.query.count()
            norm_count = NormalizedRule.query.count()
            cmdb_count = CMDBAsset.query.count()
            vlan_count = VLANNetwork.query.count()
            obj_group_count = ObjectGroup.query.count()
            obj_member_count = ObjectGroupMember.query.count()
            
            print(f"Before clearing:")
            print(f"  Raw rules: {raw_count}")
            print(f"  Normalized rules: {norm_count}")
            print(f"  CMDB assets: {cmdb_count}")
            print(f"  VLAN networks: {vlan_count}")
            print(f"  Object groups: {obj_group_count}")
            print(f"  Object group members: {obj_member_count}")
            
            # Delete all records (order matters due to foreign keys)
            ObjectGroupMember.query.delete()
            ObjectGroup.query.delete()
            NormalizedRule.query.delete()
            RawFirewallRule.query.delete()
            VLANNetwork.query.delete()
            CMDBAsset.query.delete()
            
            # Commit the changes
            db.session.commit()
            
            print(f"\n✅ Database cleared successfully!")
            print(f"All tables are now empty and ready for fresh data import.")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error clearing database: {e}")
            raise

if __name__ == "__main__":
    clear_database()