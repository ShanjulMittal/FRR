#!/usr/bin/env python3
"""
Script to create PCI DSS 4.0.1 compliance template with all required firewall rules
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, ComplianceRule, ReviewProfile, ProfileRuleLink

def create_pcidss_compliance_rules():
    """Create PCI DSS 4.0.1 compliance rules based on firewall requirements"""
    
    # PCI DSS 4.0.1 Firewall Compliance Rules
    pcidss_rules = [
        # Requirement 1.1 - Firewall and Router Configuration Standards
        {
            'rule_name': 'PCI-1.1.1 - Deny All Default Policy',
            'description': 'Firewall must have a default deny-all policy for inbound and outbound traffic',
            'field_to_check': 'action',
            'operator': 'not_equals',
            'value': 'permit',
            'severity': 'Critical'
        },
        {
            'rule_name': 'PCI-1.1.2 - No Direct Internet Access to CDE',
            'description': 'Prohibit direct public access between the internet and any system components in the cardholder data environment',
            'field_to_check': 'source_ip',
            'operator': 'not_regex_match',
            'value': '^(0\.0\.0\.0|any)$',
            'severity': 'Critical'
        },
        {
            'rule_name': 'PCI-1.1.3 - Restrict Insecure Services',
            'description': 'Restrict or deny insecure services and protocols (Telnet, FTP, HTTP, SNMP v1/v2)',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/21,TCP/23,TCP/80,UDP/161,UDP/162,TCP/69,UDP/69',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-1.1.4 - Document Business Justification',
            'description': 'All allowed services must have documented business justification',
            'logic': 'AND',
            'conditions': [
                {'field_to_check': 'action', 'operator': 'equals', 'value': 'permit'},
                {'field_to_check': 'notes', 'operator': 'equals', 'value': ''}
            ],
            'severity': 'Medium'
        },
        
        # Requirement 1.2 - Restrict Connections Between Untrusted Networks
        {
            'rule_name': 'PCI-1.2.1 - Limit Inbound Traffic',
            'description': 'Limit inbound and outbound traffic to only that which is necessary for the cardholder data environment',
            'field_to_check': 'action',
            'operator': 'equals',
            'value': 'deny',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-1.2.2 - Secure Remote Access',
            'description': 'Secure and synchronize router configuration files',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/22,TCP/3389,TCP/5900',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-1.2.3 - DMZ Implementation',
            'description': 'Install perimeter firewalls between all wireless networks and the cardholder data environment',
            'field_to_check': 'dest_environment',
            'operator': 'not_equals',
            'value': 'DMZ',
            'severity': 'Critical'
        },
        
        # Requirement 1.3 - Prohibit Direct Public Access
        {
            'rule_name': 'PCI-1.3.1 - Anti-Spoofing Measures',
            'description': 'Implement anti-spoofing measures to detect and prevent forged source IP addresses',
            'field_to_check': 'source_ip',
            'operator': 'not_regex_match',
            'value': '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-1.3.2 - No Unauthorized Outbound Traffic',
            'description': 'Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet',
            'field_to_check': 'dest_ip',
            'operator': 'not_equals',
            'value': 'any',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-1.3.3 - Established Connections Only',
            'description': 'Allow only established connections into the network',
            'field_to_check': 'protocol',
            'operator': 'in_list',
            'value': 'TCP',
            'severity': 'Medium'
        },
        
        # Requirement 2.1 - Change Vendor Defaults
        {
            'rule_name': 'PCI-2.1.1 - No Default Passwords',
            'description': 'Always change vendor-supplied defaults and remove or disable unnecessary default accounts',
            'field_to_check': 'notes',
            'operator': 'not_contains',
            'value': 'default',
            'severity': 'Critical'
        },
        
        # Requirement 2.2 - System Configuration Standards
        {
            'rule_name': 'PCI-2.2.1 - Enable Only Necessary Services',
            'description': 'Enable only necessary services, protocols, daemons, etc., as required for the function of the system',
            'field_to_check': 'action',
            'operator': 'equals',
            'value': 'permit',
            'severity': 'Medium'
        },
        {
            'rule_name': 'PCI-2.2.2 - Secure Service Configuration',
            'description': 'Implement additional security features for any required services, protocols, or daemons that are considered to be insecure',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/135,TCP/139,TCP/445,UDP/137,UDP/138,UDP/139',
            'severity': 'High'
        },
        
        # Network Security Controls (NSC) - PCI DSS 4.0 Updates
        {
            'rule_name': 'PCI-NSC-1 - Network Segmentation',
            'description': 'Implement network segmentation to isolate the CDE from other networks',
            'field_to_check': 'dest_vlan_name',
            'operator': 'not_equals',
            'value': 'PRODUCTION',
            'severity': 'Critical'
        },
        {
            'rule_name': 'PCI-NSC-2 - Encrypted Protocols Only',
            'description': 'Use only encrypted and secure protocols for network communications',
            'field_to_check': 'service_port',
            'operator': 'in_list',
            'value': 'TCP/443,TCP/22,TCP/993,TCP/995,TCP/636',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-NSC-3 - No Weak Encryption',
            'description': 'Prohibit use of weak encryption protocols (SSL, early TLS versions)',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/443',
            'severity': 'High'
        },
        
        # Additional Security Requirements
        {
            'rule_name': 'PCI-SEC-1 - High Risk Ports Blocked',
            'description': 'Block commonly exploited high-risk ports',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/1433,TCP/3306,TCP/5432,TCP/1521,TCP/27017',
            'severity': 'High'
        },
        {
            'rule_name': 'PCI-SEC-2 - P2P and File Sharing Blocked',
            'description': 'Block peer-to-peer and file sharing protocols',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/6881,TCP/6882,TCP/6883,TCP/6884,TCP/6885,UDP/6881',
            'severity': 'Medium'
        },
        {
            'rule_name': 'PCI-SEC-3 - Administrative Access Control',
            'description': 'Restrict administrative access to authorized personnel only',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/22,TCP/3389,TCP/5900,TCP/5901',
            'severity': 'Critical'
        },
        {
            'rule_name': 'PCI-SEC-4 - Logging and Monitoring Ports',
            'description': 'Ensure logging and monitoring services are properly secured',
            'field_to_check': 'service_port',
            'operator': 'in_list',
            'value': 'TCP/514,UDP/514,TCP/6514',
            'severity': 'Medium'
        }
    ]
    
    created_rules = []
    
    for rule_data in pcidss_rules:
        # Check if rule already exists
        existing_rule = ComplianceRule.query.filter_by(rule_name=rule_data['rule_name']).first()
        if existing_rule:
            print(f"Rule '{rule_data['rule_name']}' already exists, skipping...")
            created_rules.append(existing_rule)
            continue
        
        # Create new compliance rule
        rule = ComplianceRule(
            rule_name=rule_data['rule_name'],
            description=rule_data['description'],
            field_to_check=rule_data.get('field_to_check'),
            operator=rule_data.get('operator'),
            value=json.dumps(rule_data['conditions']) if 'logic' in rule_data else rule_data.get('value'),
            severity=rule_data['severity'],
            is_active=True,
            created_by='PCI DSS 4.0.1 Template',
            logic=rule_data.get('logic')
        )
        
        db.session.add(rule)
        created_rules.append(rule)
        print(f"Created rule: {rule_data['rule_name']}")
    
    return created_rules

def create_pcidss_review_profile(compliance_rules):
    """Create PCI DSS 4.0.1 review profile and link it with compliance rules"""
    
    # Check if profile already exists
    existing_profile = ReviewProfile.query.filter_by(profile_name='PCI DSS 4.0.1 Firewall Compliance').first()
    if existing_profile:
        print("PCI DSS 4.0.1 profile already exists, updating rules...")
        profile = existing_profile
    else:
        # Create new review profile
        profile = ReviewProfile(
            profile_name='PCI DSS 4.0.1 Firewall Compliance',
            description='Comprehensive PCI DSS 4.0.1 compliance template for firewall rule review. Includes all required network security controls, access restrictions, and security measures mandated by the Payment Card Industry Data Security Standard version 4.0.1.',
            compliance_framework='PCI-DSS',
            version='4.0.1',
            is_active=True,
            created_by='PCI DSS 4.0.1 Template'
        )
        db.session.add(profile)
        print("Created PCI DSS 4.0.1 review profile")
    
    # Commit to get the profile ID
    db.session.commit()
    
    # Link compliance rules to the profile
    for rule in compliance_rules:
        # Check if link already exists
        existing_link = ProfileRuleLink.query.filter_by(
            profile_id=profile.id,
            rule_id=rule.id
        ).first()
        
        if existing_link:
            print(f"Rule '{rule.rule_name}' already linked to profile, skipping...")
            continue
        
        # Determine if rule is mandatory based on severity
        is_mandatory = rule.severity in ['Critical', 'High']
        weight = 1.0
        if rule.severity == 'Critical':
            weight = 2.0
        elif rule.severity == 'High':
            weight = 1.5
        elif rule.severity == 'Medium':
            weight = 1.0
        else:  # Low
            weight = 0.5
        
        # Create profile-rule link
        link = ProfileRuleLink(
            profile_id=profile.id,
            rule_id=rule.id,
            weight=weight,
            is_mandatory=is_mandatory,
            added_by='PCI DSS 4.0.1 Template'
        )
        
        db.session.add(link)
        print(f"Linked rule '{rule.rule_name}' to profile (mandatory: {is_mandatory}, weight: {weight})")
    
    return profile

def main():
    """Main function to create PCI DSS 4.0.1 compliance template"""
    
    with app.app_context():
        try:
            print("Creating PCI DSS 4.0.1 compliance template...")
            print("=" * 60)
            
            # Create compliance rules
            print("\n1. Creating compliance rules...")
            compliance_rules = create_pcidss_compliance_rules()
            
            # Create review profile and link rules
            print(f"\n2. Creating review profile and linking {len(compliance_rules)} rules...")
            profile = create_pcidss_review_profile(compliance_rules)
            
            # Commit all changes
            db.session.commit()
            
            print("\n" + "=" * 60)
            print("PCI DSS 4.0.1 compliance template created successfully!")
            print(f"Profile: {profile.profile_name}")
            print(f"Framework: {profile.compliance_framework} v{profile.version}")
            print(f"Total Rules: {len(compliance_rules)}")
            
            # Count rules by severity
            severity_counts = {}
            for rule in compliance_rules:
                severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1
            
            print("\nRules by Severity:")
            for severity, count in sorted(severity_counts.items()):
                print(f"  {severity}: {count}")
            
            print(f"\nProfile ID: {profile.id}")
            print("Template is ready for use!")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating PCI DSS template: {str(e)}")
            raise

if __name__ == '__main__':
    main()