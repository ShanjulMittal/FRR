
from app import app
from models import ComplianceRule

with app.app_context():
    rule = ComplianceRule.query.get(50)
    print(f"ID: {rule.id}")
    print(f"Name: {rule.rule_name}")
    print(f"Value: {rule.value}")
