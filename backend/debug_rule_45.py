
from app import app
from models import ComplianceRule
import json

def debug_rule():
    with app.app_context():
        rule = ComplianceRule.query.get(45)
        if not rule:
            print("Rule 45 not found")
            return

        print(f"Rule ID: {rule.id}")
        print(f"Name: {rule.rule_name}")
        print(f"Field to Check: {rule.field_to_check}")
        print(f"Operator: {rule.operator}")
        print(f"Value: {rule.value}")

if __name__ == "__main__":
    debug_rule()
