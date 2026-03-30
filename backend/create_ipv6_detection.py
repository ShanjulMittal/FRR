#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, ComplianceRule, ReviewProfile, ProfileRuleLink

RULE_NAME = 'Detect IPv6 in source or destination'
PROFILE_NAME = 'IPv6 Detection'

def create_ipv6_rule():
    existing = ComplianceRule.query.filter_by(rule_name=RULE_NAME).first()
    if existing:
        return existing
    value_json = {
        'logic': 'OR',
        'conditions': [
            {
                'logic': 'OR',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'regex_match', 'value': '(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}'},
                    {'field': 'source_ip', 'operator': 'regex_match', 'value': '(?i)^[0-9a-f]{32}(?:/[0-9]{1,3})?$'},
                    {'field': 'source_ip', 'operator': 'contains', 'value': 'ipv6'},
                    {'field': 'source_ip', 'operator': 'contains', 'value': 'ip6'}
                ]
            },
            {
                'logic': 'OR',
                'conditions': [
                    {'field': 'dest_ip', 'operator': 'regex_match', 'value': '(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}'},
                    {'field': 'dest_ip', 'operator': 'regex_match', 'value': '(?i)^[0-9a-f]{32}(?:/[0-9]{1,3})?$'},
                    {'field': 'dest_ip', 'operator': 'contains', 'value': 'ipv6'},
                    {'field': 'dest_ip', 'operator': 'contains', 'value': 'ip6'}
                ]
            }
        ]
    }
    import json
    rule = ComplianceRule(
        rule_name=RULE_NAME,
        description='Flags rules where source_ip or dest_ip contains an IPv6 address',
        field_to_check='source_ip',
        operator='composite',
        value=json.dumps(value_json),
        severity='Medium',
        is_active=True,
        created_by='system'
    )
    db.session.add(rule)
    db.session.commit()
    return rule

def upgrade_ipv6_rule():
    import json
    rule = ComplianceRule.query.filter_by(rule_name=RULE_NAME).first()
    if not rule:
        return None
    value_json = {
        'logic': 'OR',
        'conditions': [
            {
                'logic': 'OR',
                'conditions': [
                    {'field': 'source_ip', 'operator': 'regex_match', 'value': '(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}'},
                    {'field': 'source_ip', 'operator': 'regex_match', 'value': '(?i)^[0-9a-f]{32}(?:/[0-9]{1,3})?$'},
                    {'field': 'source_ip', 'operator': 'contains', 'value': 'ipv6'},
                    {'field': 'source_ip', 'operator': 'contains', 'value': 'ip6'}
                ]
            },
            {
                'logic': 'OR',
                'conditions': [
                    {'field': 'dest_ip', 'operator': 'regex_match', 'value': '(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}'},
                    {'field': 'dest_ip', 'operator': 'regex_match', 'value': '(?i)^[0-9a-f]{32}(?:/[0-9]{1,3})?$'},
                    {'field': 'dest_ip', 'operator': 'contains', 'value': 'ipv6'},
                    {'field': 'dest_ip', 'operator': 'contains', 'value': 'ip6'}
                ]
            }
        ]
    }
    rule.value = json.dumps(value_json)
    db.session.commit()
    return rule

def create_profile_and_link(rule):
    profile = ReviewProfile.query.filter_by(profile_name=PROFILE_NAME).first()
    if not profile:
        profile = ReviewProfile(
            profile_name=PROFILE_NAME,
            description='Profile to detect IPv6 addresses in firewall rules',
            compliance_framework='Custom',
            version='v1',
            is_active=True,
            created_by='system'
        )
        db.session.add(profile)
        db.session.commit()
    link = ProfileRuleLink.query.filter_by(profile_id=profile.id, rule_id=rule.id).first()
    if not link:
        link = ProfileRuleLink(
            profile_id=profile.id,
            rule_id=rule.id,
            weight=1.0,
            is_mandatory=True,
            added_by='system'
        )
        db.session.add(link)
        db.session.commit()
    return profile

def main():
    with app.app_context():
        rule = create_ipv6_rule()
        upgrade_ipv6_rule()
        profile = create_profile_and_link(rule)
        print('IPv6 rule created:', rule.id)
        print('Profile:', profile.id, profile.profile_name)

if __name__ == '__main__':
    main()