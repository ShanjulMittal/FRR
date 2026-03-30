
from app import app, db
from models import ReviewProfile, ComplianceRule

with app.app_context():
    profiles = ReviewProfile.query.all()
    print(f"Found {len(profiles)} profiles:")
    for p in profiles:
        print(f"- ID: {p.id}, Name: {p.profile_name}, Framework: {p.compliance_framework}")
        for link in p.rule_links:
             rule = ComplianceRule.query.get(link.rule_id)
             print(f"  - Rule: {rule.rule_name} (ID: {rule.id})")
