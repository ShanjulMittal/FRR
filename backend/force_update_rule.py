
from app import app, db
from models import ComplianceRule

with app.app_context():
    # Force update the rule in DB by running the seed block
    # Actually, the seed block only runs on app startup or if we manually trigger it.
    # But since we modified app.py, the Flask reloader might have picked it up if it was running.
    # However, to be safe, let's manually update the rule in the DB.
    
    import json
    
    rule = ComplianceRule.query.filter_by(rule_name='Business Documentation - Change reference').first()
    if rule:
        composite_logic = {
            "logic": "AND",
            "conditions": [
                {
                    "field": "action",
                    "operator": "not_contains",
                    "value": "disabled"
                },
                {
                    "field": "rule_name",
                    "operator": "not_regex_match",
                    "value": r"(CHG|CTASK|CMR|AU-C|ECMR|CR|18|19|17|16|15|14|13|12)[-_ ]?\d+"
                }
            ]
        }
        rule.operator = 'composite'
        rule.value = json.dumps(composite_logic)
        rule.description = 'Rule must contain a valid Change reference (CHG/CTASK/CMR/AU-C/ECMR/CR or starting with 12-19) OR be disabled'
        db.session.commit()
        print("Rule updated successfully in DB.")
    else:
        print("Rule not found in DB.")
