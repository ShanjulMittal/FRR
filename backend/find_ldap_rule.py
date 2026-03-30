
from app import app, db
from models import ComplianceRule

with app.app_context():
    rules = ComplianceRule.query.filter(
        (ComplianceRule.rule_name.ilike('%LDAP%')) | 
        (ComplianceRule.description.ilike('%LDAP%')) |
        (ComplianceRule.value.ilike('%389%'))
    ).all()
    
    print(f"Found {len(rules)} rules:")
    for r in rules:
        print(f"ID: {r.id}")
        print(f"Name: {r.rule_name}")
        print(f"Description: {r.description}")
        print(f"Field: {r.field_to_check}")
        print(f"Operator: {r.operator}")
        print(f"Value: {r.value}")
        print("-" * 20)
