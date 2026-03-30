from app import app, db
from models import ComplianceRule

app.app_context().push()

r = ComplianceRule.query.get(46)
if r:
    print(f"Old Rule: {r.operator} {r.value}")
    
    # Revert to original logic
    r.operator = 'less_than_or_equal'
    r.value = '0'
    r.description = "Zero Hit Count (exempt if missing)"
    
    db.session.commit()
    print("Rule 46 reverted successfully.")
    
    # Verify
    r_new = ComplianceRule.query.get(46)
    print(f"New Rule: {r_new.operator} {r_new.value}")
else:
    print("Rule 46 not found.")
