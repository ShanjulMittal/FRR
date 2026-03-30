#!/usr/bin/env python3
"""
Script to create ISO/IEC 27001:2022 network security controls template
with a practical set of firewall/comms rules and a review profile.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, ComplianceRule, ReviewProfile, ProfileRuleLink

def create_iso27001_compliance_rules():
    """Create ISO/IEC 27001:2022 network security controls rules."""
    iso_rules_data = [
        {
            'rule_name': 'ISO-NS-1 - Default Deny Policy',
            'description': 'Enforce default deny-all policy for inbound and outbound traffic per least privilege.',
            'field_to_check': 'action',
            'operator': 'not_equals',
            'value': 'permit',
            'severity': 'High'
        },
        {
            'rule_name': 'ISO-NS-2 - Segmentation of Sensitive Networks',
            'description': 'Prevent direct access to sensitive network segments (e.g., production, admin).',
            'field_to_check': 'source_ip',
            'operator': 'not_regex_match',
            'value': '^(0\\.0\\.0\\.0|any)$',
            'severity': 'Critical'
        },
        {
            'rule_name': 'ISO-NS-3 - Restrict Insecure Protocols',
            'description': 'Disallow insecure protocols such as Telnet, FTP, HTTP, and SNMP v1/v2.',
            'field_to_check': 'service_port',
            'operator': 'not_in_list',
            'value': 'TCP/21,TCP/23,TCP/80,UDP/161,UDP/162,TCP/69,UDP/69',
            'severity': 'High'
        },
        {
            'rule_name': 'ISO-NS-4 - Allow Only Required Services',
            'description': 'Permit only explicitly approved business services with documented justification.',
            'field_to_check': 'service_name',
            'operator': 'regex_match',
            'value': '^(HTTPS|SSH|RDP|DNS|NTP)$',
            'severity': 'Medium'
        },
        {
            'rule_name': 'ISO-NS-5 - Logging Enabled for Permit and Deny',
            'description': 'Enable logging for accepted and denied connections to a central log system.',
            'field_to_check': 'logging',
            'operator': 'equals',
            'value': 'enabled',
            'severity': 'Medium'
        },
        {
            'rule_name': 'ISO-NS-6 - Management Access Restricted',
            'description': 'Restrict management/admin access to known bastion or management IP ranges.',
            'field_to_check': 'dest_ip',
            'operator': 'regex_match',
            'value': '^(10\\.0\\.0\\.0/24|192\\.168\\.100\\.0/24)$',
            'severity': 'High'
        },
        {
            'rule_name': 'ISO-NS-7 - No Any-Any Rules',
            'description': 'Explicitly deny overly permissive any-any rules to reduce risk.',
            'field_to_check': 'source_ip',
            'operator': 'not_equals',
            'value': 'any',
            'severity': 'High'
        },
        {
            'rule_name': 'ISO-NS-8 - Secure Remote Access',
            'description': 'Ensure remote access uses secure protocols (e.g., SSH, HTTPS) and ports.',
            'field_to_check': 'service_port',
            'operator': 'in_list',
            'value': 'TCP/22,TCP/443',
            'severity': 'Medium'
        }
    ]

    created_rules = []
    for rule_data in iso_rules_data:
        existing = ComplianceRule.query.filter_by(rule_name=rule_data['rule_name']).first()
        if existing:
            created_rules.append(existing)
            continue
        rule = ComplianceRule(
            rule_name=rule_data['rule_name'],
            description=rule_data['description'],
            field_to_check=rule_data['field_to_check'],
            operator=rule_data['operator'],
            value=rule_data['value'],
            severity=rule_data['severity'],
            is_active=True,
            created_by='ISO 27001 Template'
        )
        db.session.add(rule)
        created_rules.append(rule)
    return created_rules


def create_iso27001_review_profile(compliance_rules):
    """Create ISO/IEC 27001:2022 review profile and link rules."""
    existing_profile = ReviewProfile.query.filter_by(profile_name='ISO/IEC 27001:2022 Network Security Controls').first()
    if existing_profile:
        profile = existing_profile
    else:
        profile = ReviewProfile(
            profile_name='ISO/IEC 27001:2022 Network Security Controls',
            description=('Network security control baseline aligned to ISO/IEC 27001:2022. '
                         'Covers segmentation, secure protocols, logging, and least privilege.'),
            compliance_framework='ISO-27001',
            version='2022',
            is_active=True,
            created_by='ISO 27001 Template'
        )
        db.session.add(profile)
        db.session.commit()

    # Link rules
    for rule in compliance_rules:
        existing_link = ProfileRuleLink.query.filter_by(profile_id=profile.id, rule_id=rule.id).first()
        if existing_link:
            continue
        link = ProfileRuleLink(
            profile_id=profile.id,
            rule_id=rule.id,
            weight=1.0,
            is_mandatory=True,
            added_by='system'
        )
        db.session.add(link)
    return profile


def main():
    with app.app_context():
        rules = create_iso27001_compliance_rules()
        profile = create_iso27001_review_profile(rules)
        db.session.commit()
        print('ISO 27001 template created:', profile.profile_name)

if __name__ == '__main__':
    main()