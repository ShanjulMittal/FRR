from app import app, db
from models import ComplianceRule
import json

app.app_context().push()

r = ComplianceRule.query.get(46)
if r:
    print(f"Old Rule: {r.operator} {r.value}")
    
    # Logic: (hit_count > 0) OR (hit_count is empty)
    composite_value = {
        "logic": "OR",
        "conditions": [
            {
                "field": "hit_count",
                "operator": "greater_than",
                "value": "0"
            },
            {
                "field": "hit_count",
                "operator": "is_empty",
                "value": ""
            }
        ]
    }
    
    r.operator = 'composite'
    r.value = json.dumps(composite_value)
    r.description = "Ensure hit count is greater than 0, or exempt if missing"
    
    db.session.commit()
    print("Rule 46 updated successfully.")
    
    # Verify
    r_new = ComplianceRule.query.get(46)
    print(f"New Rule: {r_new.operator} {r_new.value}")
else:
    print("Rule 46 not found.")
