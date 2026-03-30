
import sys
import os
# Add backend directory to path so we can import directly
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app import app
from models import db, ComplianceRule, ServicePortMapping

def check_rule_and_mappings():
    with app.app_context():
        # Check Rule 49
        rule = db.session.get(ComplianceRule, 49)
        if rule:
            print(f"Rule 49: {rule.rule_name}")
            print(f"Type: {rule.operator}")
            print(f"Value: {rule.value}")
        else:
            print("Rule 49 not found")

        # Check Service Mappings
        mappings = ServicePortMapping.query.filter_by(category='Database').all()
        print(f"\nDB Port Mappings found: {len(mappings)}")
        for m in mappings:
            print(f" - {m.port_number} ({m.service_name})")

if __name__ == "__main__":
    check_rule_and_mappings()
