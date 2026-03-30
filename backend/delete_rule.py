import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, ComplianceRule, ProfileRuleLink

def delete_rule(rule_name):
    with app.app_context():
        rule = ComplianceRule.query.filter_by(rule_name=rule_name).first()
        if rule:
            # Delete all links to this rule from profiles
            links = ProfileRuleLink.query.filter_by(rule_id=rule.id).all()
            for link in links:
                db.session.delete(link)
            
            db.session.delete(rule)
            db.session.commit()
            print(f"Rule '{rule_name}' and its links deleted successfully.")
        else:
            print(f"Rule '{rule_name}' not found.")

if __name__ == '__main__':
    delete_rule('PCI-1.1.4 - Document Business Justification')