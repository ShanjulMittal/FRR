import json
from typing import Any

from app import app
from models import ComplianceRule, db
from compliance_engine import compliance_engine


class DummyRule:
    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            setattr(self, k, v)
        if not hasattr(self, 'custom_fields_data'):
            self.custom_fields_data = None
        if not hasattr(self, 'raw_rule'):
            self.raw_rule = None


def run_case(title: str, normalized_rule: Any, comp_rule: ComplianceRule) -> None:
    result = compliance_engine.evaluate_rule_against_compliance(normalized_rule, comp_rule)
    status = 'PASS' if result['compliant'] else 'VIOLATION'
    print(f"{title}: {status}")
    print(json.dumps(result, indent=2))


def main():
    with app.app_context():
        rule58 = ComplianceRule.query.get(58)
        assert rule58 is not None
        rule59 = ComplianceRule.query.get(59)
        rule60 = ComplianceRule.query.get(60)
        rule61 = ComplianceRule.query.get(61)
        assert rule59 and rule60 and rule61
        rule47 = ComplianceRule.query.get(47)
        rule49 = ComplianceRule.query.get(49)
        rule50 = ComplianceRule.query.get(50)
        rule55 = ComplianceRule.query.get(55)
        rule56 = ComplianceRule.query.get(56)
        rule57 = ComplianceRule.query.get(57)
        assert rule47 and rule49 and rule50 and rule55 and rule56 and rule57

        case1 = DummyRule(action='permit', source_ip='any', dest_ip='any', service_port='any', dest_port='', protocol='ip')
        run_case('Any-Any-Any Permit', case1, rule58)

        case2 = DummyRule(action='permit', source_ip='10.0.0.1', dest_ip='10.0.0.2', service_port='443', dest_port='443', protocol='tcp')
        run_case('Specific Permit', case2, rule58)

        case3 = DummyRule(action='permit', source_ip='10.0.0.1', dest_ip='10.0.0.2', service_port='', dest_port='22', protocol='any')
        run_case('Specific Src/Dst, Any Protocol', case3, rule58)

        # Rule 59: Any Source + Specific Dest + Any Service
        r59_v = DummyRule(action='permit', source_ip='any', dest_ip='10.0.0.5', service_port='any', dest_port='')
        run_case('R59 Violation (Any src, Specific dest, Any service)', r59_v, rule59)
        r59_p = DummyRule(action='permit', source_ip='any', dest_ip='any', service_port='443', dest_port='443')
        run_case('R59 Pass (Any dest, specific service)', r59_p, rule59)

        # Rule 60: Specific Source + Any Dest + Any Service
        r60_v = DummyRule(action='permit', source_ip='10.0.0.1', dest_ip='any', service_port='any', dest_port='')
        run_case('R60 Violation (Specific src, Any dest, Any service)', r60_v, rule60)
        r60_p = DummyRule(action='permit', source_ip='any', dest_ip='any', service_port='443', dest_port='443')
        run_case('R60 Pass (Any src, Any dest, specific service)', r60_p, rule60)

        # Rule 61: Permit Requires Specific Service
        r61_v = DummyRule(action='permit', source_ip='10.0.0.1', dest_ip='10.0.0.2', service_port='any', dest_port='')
        run_case('R61 Violation (Service any/empty)', r61_v, rule61)
        r61_p = DummyRule(action='permit', source_ip='10.0.0.1', dest_ip='10.0.0.2', service_port='443', dest_port='443')
        run_case('R61 Pass (Specific ports)', r61_p, rule61)

        # Rule 47: Internet HTTP/80 or non-443
        r47_v1 = DummyRule(action='permit', source_ip='any', protocol='tcp', dest_port='80')
        run_case('R47 Violation (80 from internet)', r47_v1, rule47)
        r47_v2 = DummyRule(action='permit', source_ip='any', protocol='tcp', dest_port='8080')
        run_case('R47 Violation (non-443 from internet)', r47_v2, rule47)
        r47_p = DummyRule(action='permit', source_ip='any', protocol='tcp', dest_port='443')
        run_case('R47 Pass (443 from internet)', r47_p, rule47)

        # Rule 49: DB ports from User/WiFi VLANs
        r49_v = DummyRule(action='permit', dest_port='1521', source_vlan_name='user-vlan')
        run_case('R49 Violation (DB port from user VLAN)', r49_v, rule49)
        r49_p = DummyRule(action='permit', dest_port='1521', source_vlan_name='server-segment')
        run_case('R49 Pass (DB port from server segment)', r49_p, rule49)

        # Rule 50: RDP/SSH only from Citrix or PIM/PAM
        r50_v = DummyRule(action='permit', service_port='3389', source_owner='Finance', source_hostname='app01')
        run_case('R50 Violation (RDP not from Citrix/PIM/PAM)', r50_v, rule50)
        r50_p = DummyRule(action='permit', service_port='22', source_owner='Citrix', source_hostname='citrix-gw')
        run_case('R50 Pass (SSH from Citrix)', r50_p, rule50)

        # Rule 55: High risk ports 137/139/445
        r55_v = DummyRule(action='permit', dest_port='445')
        run_case('R55 Violation (445 exposed)', r55_v, rule55)
        r55_p = DummyRule(action='permit', dest_port='443')
        run_case('R55 Pass (no high risk port)', r55_p, rule55)

        # Rule 56: Restricted services FTP/TELNET/SMTP/TFTP
        r56_v = DummyRule(action='permit', service_name='FTP')
        run_case('R56 Violation (FTP exposed)', r56_v, rule56)
        r56_p = DummyRule(action='permit', service_name='HTTPS', dest_port='443')
        run_case('R56 Pass (secure service)', r56_p, rule56)

        # Rule 57: Unsecured LDAP (389)
        r57_v = DummyRule(action='permit', dest_port='389')
        run_case('R57 Violation (LDAP 389 exposed)', r57_v, rule57)
        r57_p = DummyRule(action='permit', dest_port='636')
        run_case('R57 Pass (LDAPS 636)', r57_p, rule57)


if __name__ == '__main__':
    main()