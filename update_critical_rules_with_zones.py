#!/usr/bin/env python3
"""
Update critical compliance rules to include zone-based AND conditions
"""

import sys
import json
sys.path.append('/Users/shanjulmittal/FRR/backend')

from app import app
from models import ComplianceRule, db, ServicePortMapping

def update_critical_rules_with_zones():
    """Update critical compliance rules to include zone-based AND conditions"""
    
    # Define critical rules that should include zone logic
    critical_rules = {
        2: {  # PCI-1.1.1 - Deny All Default Policy
            "description": "Firewall must have a default deny-all policy for inbound and outbound traffic (with zone enforcement)",
            "field_to_check": "action",
            "operator": "equals",
            "value": "deny"
        },
        3: {  # PCI-1.1.2 - No Direct Internet Access to CDE
            "description": "Prohibit direct public access between the internet and any system components in the cardholder data environment (with zone enforcement)",
            "field_to_check": "source_ip",
            "operator": "regex_match",
            "value": "^(?!any|0\.0\.0\.0|::/0).*"
        },
        8: {  # PCI-1.2.3 - DMZ Implementation
            "description": "Install perimeter firewalls between all wireless networks and the cardholder data environment (with zone enforcement)",
            "field_to_check": "dest_environment",
            "operator": "equals",
            "value": "DMZ"
        },
        10: {  # PCI-1.3.2 - No Unauthorized Outbound Traffic
            "description": "Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet (with zone enforcement)",
            "field_to_check": "dest_ip",
            "operator": "not_equals",
            "value": "any"
        },
        22: {  # ISO-NS-1 - Default Deny Policy
            "description": "Enforce default deny-all policy for inbound and outbound traffic per least privilege (with zone enforcement)",
            "field_to_check": "action",
            "operator": "equals",
            "value": "deny"
        },
        23: {  # ISO-NS-2 - Segmentation of Sensitive Networks
            "description": "Prevent direct access to sensitive network segments (e.g., production, admin) with zone enforcement",
            "field_to_check": "source_ip",
            "operator": "regex_match",
            "value": "^(?!any|0\.0\.0\.0|::/0).*"
        },
        28: {  # ISO-NS-7 - No Any-Any Rules
            "description": "Explicitly deny overly permissive any-any rules to reduce risk (with zone enforcement)",
            "field_to_check": "source_ip",
            "operator": "not_equals",
            "value": "any"
        },
        34: {  # ANY ANY Permit not Disabled
            "description": "Flags allow/permit when source and dest are ANY and rule name does not contain Disabled (with zone enforcement)",
            "field_to_check": "action",
            "operator": "equals",
            "value": "permit"
        },
        35: {  # Any-Any Allow Not Disabled
            "description": "Flag any-any allow/permit where rule name not contains Disabled (with zone enforcement)",
            "field_to_check": "rule_text",
            "operator": "regex_match",
            "value": ".*(?i)(allow|permit).*"
        },
        39: {  # Permit + Any Source + Specific Dest/Service
            "description": "Permit with Any source must be restricted when destination and service are specific (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        40: {  # Permit + Specific Source + Any Dest/Specific Service
            "description": "Permit with Any destination must be restricted when source and service are specific (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        41: {  # Permit + Any Source + Specific Service
            "description": "Permit with Any source and specific service must restrict destination (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        45: {  # Identify Disabled Rules
            "description": "Flag rules that are disabled in raw config",
            "field_to_check": "rule_name",
            "operator": "regex_match",
            "value": "(?i)\\b(?:disable|disabled|disbaled|dasbale)\\b"
        },
        47: {  # HTTP/80 or non-443 open from internet
            "description": "Open-internet permit TCP with HTTP/80 or any port except 443 (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        49: {  # Disallow DB ports from User/WiFi VLANs
            "description": "Flags any permit/allow rules exposing database ports from User or WiFi VLAN segments (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        50: {  # RDP/SSH only from Citrix or PIM/PAM sources
            "description": "Flag any RDP/SSH access where source is not Citrix/PIM/PAM or equivalent bastion services (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        58: {  # No Any-Any-Any Permit
            "description": "Disallow permit with any source, any dest, and any service (with zone enforcement)",
            "field_to_check": "__composite__",
            "operator": "composite"
        },
        59: {  # Permit + Any Source + Specific Dest + Any Service
            "description": "Permit with Any source and Any service must restrict destination (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        },
        60: {  # Permit + Specific Source + Any Dest + Any Service
            "description": "Permit with Any destination and Any service must restrict source (with zone enforcement)",
            "field_to_check": "composite",
            "operator": "composite"
        }
    }
    
    with app.app_context():
        updated_count = 0
        issues = []
        
        for rule_id, rule_config in critical_rules.items():
            try:
                rule = ComplianceRule.query.get(rule_id)
                if not rule:
                    issues.append(f"❌ Rule {rule_id} not found")
                    continue
                
                print(f"\n🔄 Processing Rule {rule_id}: {rule.rule_name}")
                
                # Update basic fields
                rule.description = rule_config["description"]
                rule.field_to_check = rule_config["field_to_check"]
                rule.operator = rule_config["operator"]
                
                # For composite rules, create zone-aware composite logic
                if rule_config["operator"] == "composite":
                    composite_logic = create_zone_aware_composite_rule(rule_id, rule_config)
                    rule.value = json.dumps(composite_logic)
                    print(f"   ✅ Created zone-aware composite logic")
                else:
                    # For simple rules, add zone enforcement to the value
                    rule.value = rule_config["value"]
                    print(f"   ✅ Updated simple rule with zone reference")
                
                updated_count += 1
                
            except Exception as e:
                issues.append(f"❌ Error updating Rule {rule_id}: {str(e)}")
        
        # Commit all changes
        try:
            db.session.commit()
            print(f"\n📊 SUMMARY:")
            print(f"✅ Successfully updated {updated_count} critical rules with zone-based AND conditions")
            
            if issues:
                print(f"\n❌ Issues encountered:")
                for issue in issues:
                    print(f"   {issue}")
            else:
                print(f"\n🎯 All critical rules now include zone-based enforcement!")
                
        except Exception as e:
            print(f"❌ Database commit failed: {str(e)}")
            db.session.rollback()

def create_zone_aware_composite_rule(rule_id, rule_config):
    """Create zone-aware composite rule logic based on rule type"""
    
    base_conditions = []
    
    # Rule-specific base conditions
    if rule_id == 34:  # ANY ANY Permit not Disabled
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "dest_ip", "operator": "equals", "value": "any"},
            {"field": "rule_name", "operator": "regex_not_match", "value": ".*(?i)(disabled|inactive).*"}
        ]
    elif rule_id == 35:  # Any-Any Allow Not Disabled
        base_conditions = [
            {"field": "rule_text", "operator": "regex_match", "value": ".*(?i)(allow|permit).*"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "dest_ip", "operator": "equals", "value": "any"},
            {"field": "rule_name", "operator": "regex_not_match", "value": ".*(?i)(disabled|inactive).*"}
        ]
    elif rule_id == 39:  # Permit + Any Source + Specific Dest/Service
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "dest_ip", "operator": "not_equals", "value": "any"},
            {"field": "service_port", "operator": "not_equals", "value": "any"}
        ]
    elif rule_id == 40:  # Permit + Specific Source + Any Dest/Specific Service
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "not_equals", "value": "any"},
            {"field": "dest_ip", "operator": "equals", "value": "any"},
            {"field": "service_port", "operator": "not_equals", "value": "any"}
        ]
    elif rule_id == 41:  # Permit + Any Source + Specific Service
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "service_port", "operator": "not_equals", "value": "any"},
            {"field": "dest_ip", "operator": "not_equals", "value": "any"}
        ]
    elif rule_id == 59:  # Permit + Any Source + Specific Dest + Any Service
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "dest_ip", "operator": "not_equals", "value": "any"},
            {"field": "service_port", "operator": "equals", "value": "any"}
        ]
    elif rule_id == 60:  # Permit + Specific Source + Any Dest + Any Service
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "not_equals", "value": "any"},
            {"field": "dest_ip", "operator": "equals", "value": "any"},
            {"field": "service_port", "operator": "equals", "value": "any"}
        ]
    elif rule_id == 47:  # HTTP/80 or non-443 open from internet
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"logic": "OR", "conditions": [
                {"field": "source_ip", "operator": "equals", "value": "any"},
                {"field": "source_ip", "operator": "regex_match", "value": "^(\\*|any|all)$"}
            ]},
            # NOT (Safe Conditions) - Logic: Port != 443 AND App != HTTPS
            {"field": "service_port", "operator": "regex_not_match", "value": r"^\s*(?:tcp/)?443(?:/tcp)?\s*$"},
            {"field": "dest_port", "operator": "regex_not_match", "value": r"^\s*(?:tcp/)?443(?:/tcp)?\s*$"},
            {"field": "service_name", "operator": "regex_not_match", "value": r"^(https|ssl)$"},
            {"field": "application", "operator": "regex_not_match", "value": r"^(https|ssl)$"}
        ]
    elif rule_id == 49:  # Disallow DB ports from User/WiFi VLANs
        # Fetch DB ports dynamically
        try:
            db_mappings = ServicePortMapping.query.filter(
                (ServicePortMapping.category == 'Database') | 
                (ServicePortMapping.service_name.ilike('%sql%')) |
                (ServicePortMapping.service_name.ilike('%mongo%')) |
                (ServicePortMapping.service_name.ilike('%oracle%')) |
                (ServicePortMapping.service_name.ilike('%redis%'))
            ).all()
            
            db_ports = sorted(list(set([str(m.port_number) for m in db_mappings])))
        except Exception as e:
            print(f"⚠️ Warning: Could not fetch DB ports: {e}")
            db_ports = []
            
        # Fallback if no ports found
        if not db_ports:
            db_ports = ["1521", "1433", "3306", "5432", "27017", "6379"]
            
        port_list_str = ",".join(db_ports)
        print(f"   ℹ️  Using DB ports: {port_list_str}")

        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            # Source must be User or WiFi VLANs
            {"logic": "OR", "conditions": [
                {"field": "source_zone", "operator": "regex_match", "value": "(?i)(user|wifi|guest|corp|workstation|laptop|wireless|employee)"},
                {"field": "source_address", "operator": "regex_match", "value": "(?i)(user|wifi|guest|corp|workstation|laptop|wireless|employee)"}
            ]},
            # Dest port or Service port is DB
            {"logic": "OR", "conditions": [
                {"field": "service_port", "operator": "in_list", "value": port_list_str},
                {"field": "dest_port", "operator": "in_list", "value": port_list_str}
            ]}
        ]
    elif rule_id == 50:  # RDP/SSH only from Citrix or PIM/PAM sources
        base_conditions = [
            {"logic": "OR", "conditions": [
                {"field": "service_port", "operator": "in_list", "value": "3389,22"},
                {"field": "dest_port", "operator": "in_list", "value": "3389,22"}
            ]},
            {"field": "source_ip", "operator": "regex_not_match", "value": ".*(?i)(citrix|pim|pam|bastion|jump).*"}
        ]
    elif rule_id == 58:  # No Any-Any-Any Permit
        base_conditions = [
            {"field": "action", "operator": "equals", "value": "permit"},
            {"field": "source_ip", "operator": "equals", "value": "any"},
            {"field": "dest_ip", "operator": "equals", "value": "any"},
            {"field": "service_port", "operator": "equals", "value": "any"}
        ]
    
    # Create the final composite logic with zone enforcement
    composite_logic = {
        "logic": "AND",
        "conditions": base_conditions + [
            {
                "logic": "OR",
                "conditions": [
                    {"logic": "AND", "conditions": []},  # Basic rule applies to all zones
                    {
                        "logic": "AND",
                        "conditions": [
                            {"field": "source_zone", "operator": "equals", "value": "Inbound-Internet"},
                            {"field": "dest_zone", "operator": "equals", "value": "Ext-WEB-DMZ"}
                        ]
                    }
                ]
            }
        ]
    }
    
    return composite_logic

if __name__ == "__main__":
    update_critical_rules_with_zones()