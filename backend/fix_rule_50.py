
import json
from app import app, db
from models import ComplianceRule

new_value = {
  "logic": "AND",
  "conditions": [
    {
      "logic": "AND",
      "conditions": [
        {
          "field": "source_ip",
          "operator": "regex_not_match",
          "value": ".*(?i)(citrix|pim|pam|bastion|jump).*"
        }
      ]
    },
    {
        "logic": "OR",
        "conditions": [
            {"field": "service_port", "operator": "contains", "value": "22,3389"},
            {"field": "dest_port", "operator": "contains", "value": "22,3389"},
            {"field": "service_name", "operator": "regex_match", "value": "(?i)(ssh|rdp)"}
        ]
    },
    {
      "field": "source_zone",
      "operator": "equals",
      "value": "Inbound-Internet"
    },
    {
      "field": "dest_zone",
      "operator": "equals",
      "value": "Ext-WEB-DMZ"
    }
  ]
}

with app.app_context():
    rule = ComplianceRule.query.get(50)
    if rule:
        print(f"Updating Rule {rule.id} ({rule.rule_name})...")
        rule.value = json.dumps(new_value)
        db.session.commit()
        print("Update successful.")
    else:
        print("Rule 50 not found.")
