
import json
import logging
import sys
import os

# Ensure we can import from current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, ComplianceRule, ReviewProfile, ProfileRuleLink

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_permutation_rules():
    with app.app_context():
        # 1. Create or Get the Profile
        profile_name = "ANY Permutations Check"
        profile = ReviewProfile.query.filter_by(profile_name=profile_name).first()
        if not profile:
            logger.info(f"Creating profile: {profile_name}")
            profile = ReviewProfile(
                profile_name=profile_name,
                description="Checks for all permutations of Source/Dest/Service being ANY",
                compliance_framework="Best Practices",
                version="1.0"
            )
            db.session.add(profile)
            db.session.commit()
        else:
            logger.info(f"Using existing profile: {profile_name}")

        # Helper definitions
        s_any_group = {
            "logic": "AND",
            "conditions": [
                {"field": "source_zone", "operator": "equals", "value": "any"},
                {"field": "source", "operator": "equals", "value": "any"}
            ]
        }
        
        d_any_group = {
            "logic": "AND",
            "conditions": [
                {"field": "dest_zone", "operator": "equals", "value": "any"},
                {"field": "destination", "operator": "equals", "value": "any"}
            ]
        }
        
        # Service ANY check
        # We use a group here to easily apply "not" if needed, or just a single condition
        p_any_condition = {"field": "service_port", "operator": "equals", "value": "any"}
        
        # Define the 7 combinations
        combinations = [
            # (Source Any?, Dest Any?, Service Any?, Name, Description)
            (True,  True,  True,  "S:Any D:Any P:Any", "Violation: Source, Destination, and Service are all ANY"),
            (True,  True,  False, "S:Any D:Any P:Spec", "Violation: Source and Destination are ANY, Service is Specific"),
            (True,  False, True,  "S:Any D:Spec P:Any", "Violation: Source is ANY, Destination is Specific, Service is ANY"),
            (True,  False, False, "S:Any D:Spec P:Spec", "Violation: Source is ANY, Destination and Service are Specific"),
            (False, True,  True,  "S:Spec D:Any P:Any", "Violation: Source is Specific, Destination and Service are ANY"),
            (False, True,  False, "S:Spec D:Any P:Spec", "Violation: Source is Specific, Destination is ANY, Service is Specific"),
            (False, False, True,  "S:Spec D:Spec P:Any", "Violation: Source and Destination are Specific, Service is ANY"),
        ]

        created_count = 0
        
        for s_any, d_any, p_any, name, desc in combinations:
            # Build root group
            root_conditions = []
            
            # Source
            if s_any:
                root_conditions.append(s_any_group)
            else:
                # Source Specific = NOT (Source Any)
                root_conditions.append({
                    "not": True,
                    "logic": "AND", # The logic inside the negated group
                    "conditions": s_any_group["conditions"]
                })
            
            # Destination
            if d_any:
                root_conditions.append(d_any_group)
            else:
                # Dest Specific = NOT (Dest Any)
                root_conditions.append({
                    "not": True,
                    "logic": "AND",
                    "conditions": d_any_group["conditions"]
                })
                
            # Service
            if p_any:
                root_conditions.append(p_any_condition)
            else:
                # Service Specific = NOT (Service Any)
                root_conditions.append({
                    "not": True,
                    "field": "service_port", 
                    "operator": "equals", 
                    "value": "any"
                })

            rule_json = {
                "logic": "AND",
                "conditions": root_conditions
            }
            
            rule_value = json.dumps(rule_json)
            
            # Check if rule exists
            existing_rule = ComplianceRule.query.filter_by(rule_name=name).first()
            if existing_rule:
                logger.info(f"Updating rule: {name}")
                existing_rule.description = desc
                existing_rule.operator = "composite"
                existing_rule.value = rule_value
                existing_rule.severity = "High" if (s_any and d_any) else "Medium"
                rule = existing_rule
            else:
                logger.info(f"Creating rule: {name}")
                rule = ComplianceRule(
                    rule_name=name,
                    description=desc,
                    severity="High" if (s_any and d_any) else "Medium",
                    field_to_check="composite",
                    operator="composite",
                    value=rule_value,
                    is_active=True
                )
                db.session.add(rule)
                db.session.flush() # Get ID
                created_count += 1
            
            # Link to profile
            link = ProfileRuleLink.query.filter_by(profile_id=profile.id, rule_id=rule.id).first()
            if not link:
                link = ProfileRuleLink(
                    profile_id=profile.id,
                    rule_id=rule.id,
                    is_mandatory=True,
                    weight=10
                )
                db.session.add(link)

        db.session.commit()
        logger.info(f"Finished. Created/Updated {len(combinations)} rules.")

if __name__ == "__main__":
    create_permutation_rules()
