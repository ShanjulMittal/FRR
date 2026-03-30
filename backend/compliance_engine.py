#!/usr/bin/env python3
"""
Compliance Rule Evaluation Engine
Evaluates normalized firewall rules against compliance rules and profiles
"""

import json
import re
import logging
import ipaddress
from typing import List, Dict, Any, Tuple
from models import db, NormalizedRule, ComplianceRule, ReviewProfile, ProfileRuleLink, CMDBAsset
from custom_fields_service import CustomFieldsService

logger = logging.getLogger(__name__)


class ComplianceEngine:
    """
    The "brain" of the compliance system - evaluates rules against compliance checks
    """
    
    def __init__(self):
        self.operators = {
            'equals': self._equals,
            'not_equals': self._not_equals,
            'contains': self._contains,
            'not_contains': self._not_contains,
            'in_list': self._in_list,
            'not_in_list': self._not_in_list,
            'regex_match': self._regex_match,
            'not_regex_match': self._not_regex_match,
            'regex_not_match': self._not_regex_match, # alias
            'starts_with': self._starts_with,
            'ends_with': self._ends_with,
            'is_empty': self._is_empty,
            'is_not_empty': self._is_not_empty,
            'greater_than': self._greater_than,
            'greater_than_or_equal': self._greater_than_or_equal,
            'less_than': self._less_than,
            'less_than_or_equal': self._less_than_or_equal
        }
        self.violation_mode = True
    
    def _extract_categories_from_assets(self, assets) -> List[str]:
        cats: List[str] = []
        for a in assets:
            try:
                add = json.loads(a.additional_data) if a.additional_data else {}
            except Exception:
                add = {}
            # case-insensitive key search
            cat_val = None
            keys = [
                'pcidss_asset_category', 'PCIDSS asset category', 'PCI DSS Category',
                'PCIDSS category', 'pcidssCategory', 'pci_category', 'pci_dss_category'
            ]
            lk = {str(k).lower(): k for k in add.keys()}
            for k in keys:
                if k.lower() in lk:
                    cat_val = add.get(lk[k.lower()])
                    break
            if not cat_val and hasattr(a, 'pcidss_asset_category'):
                cat_val = getattr(a, 'pcidss_asset_category')
            if cat_val:
                val = str(cat_val).strip()
                val = val.upper()
                # normalize variants
                if val.startswith('CATEGORY '):
                    val = val.split(' ', 1)[1]
                cats.append(val)
        # de-duplicate preserving order
        seen = set()
        res = []
        for c in cats:
            if c not in seen:
                seen.add(c)
                res.append(c)
        return res

    def _get_categories_for_fields(self, ip_field: str, hostname_field: str) -> List[str]:
        try:
            cats: List[str] = []
            tokens: List[str] = []
            for field in [ip_field or '', hostname_field or '']:
                if not field:
                    continue
                tokens.extend([t.strip() for t in re.split(r"[;,.\s|]+", field) if t.strip()])
            # Gather assets by exact IP/hostname
            assets: List[CMDBAsset] = []
            exact_ips: List[str] = []
            host_tokens: List[str] = []
            for token in tokens:
                # Normalize masked tokens like a.b.c.d_20 or a.b.c.d-M20 into CIDR
                t_clean = re.sub(r'^(?:range[_\s-]?|host[_\s-]?|h[_\s-]?|subnet[_\s-]?|network[_\s-]?)','', token, flags=re.IGNORECASE).strip()
                m_mask = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})(?:[_\-]|M)(\d{1,2})", t_clean)
                if m_mask:
                    t_clean = f"{m_mask.group(1)}/{m_mask.group(2)}"
                m_cidr_dash = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,2})", t_clean)
                if m_cidr_dash:
                    t_clean = f"{m_cidr_dash.group(1)}/{m_cidr_dash.group(2)}"
                # Exact IP
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t_clean)
                if ip_match and '/' not in t_clean:
                    exact_ips.append(ip_match.group(0))
                else:
                    # Host token
                    if not re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t_clean):
                        host_tokens.append(t_clean)
            if exact_ips:
                assets.extend(db.session.query(CMDBAsset).filter(CMDBAsset.ip_address.in_(exact_ips)).all())
            if host_tokens:
                assets.extend(db.session.query(CMDBAsset).filter(CMDBAsset.hostname.in_(host_tokens)).all())
            # CIDR networks
            for token in tokens:
                t_clean = re.sub(r'^(?:range[_\s-]?|host[_\s-]?|h[_\s-]?|subnet[_\s-]?|network[_\s-]?)','', token, flags=re.IGNORECASE).strip()
                m_mask = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})(?:[_\-]|M)(\d{1,2})", t_clean)
                if m_mask:
                    t_clean = f"{m_mask.group(1)}/{m_mask.group(2)}"
                m_cidr_dash = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,2})", t_clean)
                if m_cidr_dash:
                    t_clean = f"{m_cidr_dash.group(1)}/{m_cidr_dash.group(2)}"
                if '/' in t_clean:
                    try:
                        network = ipaddress.ip_network(t_clean, strict=False)
                        candidate_assets = []
                        try:
                            if isinstance(network, ipaddress.IPv4Network):
                                full_octets = network.prefixlen // 8
                                if full_octets >= 1:
                                    base_octets = network.network_address.exploded.split('.')[:full_octets]
                                    prefix = '.'.join(base_octets) + '.'
                                    candidate_assets = db.session.query(CMDBAsset).filter(CMDBAsset.ip_address.like(f"{prefix}%")).all()
                            else:
                                candidate_assets = db.session.query(CMDBAsset).all()
                        except Exception:
                            candidate_assets = db.session.query(CMDBAsset).all()
                        in_net = []
                        for a in candidate_assets:
                            try:
                                if a.ip_address and ipaddress.ip_address(a.ip_address) in network:
                                    in_net.append(a)
                            except Exception:
                                continue
                        assets.extend(in_net)
                    except Exception:
                        pass
            return self._extract_categories_from_assets(assets)
        except Exception:
            return []

    def evaluate_rule_against_compliance(self, normalized_rule: NormalizedRule, 
                                       compliance_rule: ComplianceRule) -> Dict[str, Any]:
        """
        Evaluate a single normalized rule against a single compliance rule
        
        Returns:
            dict: {
                'compliant': bool,
                'violation_details': str or None,
                'field_value': str,
                'expected_value': str,
                'operator': str
            }
        """
        try:
            if compliance_rule.operator == 'composite':
                try:
                    group = json.loads(compliance_rule.value)
                except Exception as e:
                    logger.error(f"Invalid composite value JSON for rule {compliance_rule.id}: {e}")
                    return {
                        'compliant': False,
                        'violation_details': 'Invalid composite JSON',
                        'field_value': '',
                        'expected_value': compliance_rule.value,
                        'operator': 'composite'
                    }
                ok, failures = self._eval_condition_group(normalized_rule, group)
                if self.violation_mode:
                    return {
                        'compliant': (not ok),
                        'violation_details': json.dumps({'matched': True, 'group': group}) if ok else None,
                        'field_value': '',
                        'expected_value': compliance_rule.value,
                        'operator': 'composite'
                    }
                else:
                    return {
                        'compliant': ok,
                        'violation_details': None if ok else json.dumps(failures),
                        'field_value': '',
                        'expected_value': compliance_rule.value,
                        'operator': 'composite'
                    }

            # Special operator that checks CMDB PCI DSS categories across source/destination
            if compliance_rule.operator == 'cmdb_category_violation':
                src_cats = self._get_categories_for_fields(
                    getattr(normalized_rule, 'source_ip', ''),
                    getattr(normalized_rule, 'source_hostname', '')
                )
                dst_cats = self._get_categories_for_fields(
                    getattr(normalized_rule, 'dest_ip', ''),
                    getattr(normalized_rule, 'dest_hostname', '')
                )
                
                action_raw = str(getattr(normalized_rule, 'action', '') or '').strip().lower()
                action_tokens = [t.strip() for t in re.split(r"[;\,\|\s]+", action_raw) if t.strip()]
                deny_block = any(t in ('deny','block','drop') for t in action_tokens)
                allow_permit = any(t in ('allow','permit') for t in action_tokens) if action_tokens else (action_raw in ('allow','permit'))
                
                violation = (('A' in src_cats and 'C' in dst_cats) or ('C' in src_cats and 'A' in dst_cats)) and allow_permit and not deny_block
                
                return {
                    'compliant': not violation,
                    'violation_details': f"PCI DSS Violation: Source categories {src_cats} -> Dest categories {dst_cats}" if violation else None,
                    'field_value': f"{src_cats}->{dst_cats}",
                    'expected_value': compliance_rule.value,
                    'operator': 'cmdb_category_violation'
                }

            # Get the field value from the normalized rule
            field_name = compliance_rule.field_to_check
            field_value = None
            
            # Check if it's a custom field
            if field_name.startswith('custom_'):
                # Extract custom field name (remove 'custom_' prefix)
                custom_field_name = field_name[7:]  # Remove 'custom_' prefix
                
                # Get custom fields data from the normalized rule
                if normalized_rule.custom_fields_data:
                    try:
                        custom_fields = json.loads(normalized_rule.custom_fields_data)
                        field_value = custom_fields.get(custom_field_name)
                    except (json.JSONDecodeError, AttributeError):
                        field_value = None
                # Fallback: compute service_count dynamically if not present
                if (field_value is None) and (custom_field_name == 'service_count'):
                    try:
                        sp = str(getattr(normalized_rule, 'service_port', '') or '')
                        dp = str(getattr(normalized_rule, 'dest_port', '') or '')
                        app_raw = str(getattr(normalized_rule, 'application', '') or '')
                        combined = f"{sp} {dp}".strip()
                        if not combined:
                            field_value = 0
                        else:
                            # import re (already imported at module level)
                            raw_tokens = re.split(r"[;,\s/|]+", combined)
                            raw_tokens = [t for t in raw_tokens if t]
                            ports_seen = set()
                            app_tokens = [t.strip().lower() for t in re.split(r"[;,\s/|]+", app_raw) if t.strip()]
                            app_tokens = [t for t in app_tokens if t not in ('any','all','*')]
                            app_count = len(dict.fromkeys(app_tokens))
                            count = 0
                            for t in raw_tokens:
                                tl = t.strip().lower()
                                if not tl:
                                    continue
                                if tl in ('any', 'all', '*'):
                                    count += 65535
                                    continue
                                m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", tl)
                                if m:
                                    try:
                                        start = int(m.group(1))
                                        end = int(m.group(2))
                                        if end >= start:
                                            count += (end - start + 1)
                                        else:
                                            count += 1
                                    except Exception:
                                        count += 1
                                    continue
                                m2 = re.fullmatch(r"(?:tcp|udp|icmp|ip)[_\-:/]?([0-9]+)", tl)
                                if m2:
                                    p = m2.group(1)
                                    if p not in ports_seen:
                                        ports_seen.add(p)
                                        count += 1
                                    continue
                                if re.fullmatch(r"\d+", tl):
                                    if tl not in ports_seen:
                                        ports_seen.add(tl)
                                        count += 1
                                    continue
                                # ignore non-port tokens here (service names/app)
                            field_value = count
                    except Exception:
                        field_value = 0
            else:
                # Standard field
                field_value = getattr(normalized_rule, field_name, None)
                # Allow synthetic fields mapped from raw_rule
                if field_value is None and field_name in ('rule_text','raw_text'):
                    try:
                        raw = getattr(normalized_rule, 'raw_rule', None)
                        if raw is not None:
                            field_value = getattr(raw, field_name, None)
                    except Exception:
                        field_value = None
                # Fallback: if still None, try custom_fields_data by direct key (e.g., 'hit_count')
                if field_value is None:
                    try:
                        cfd = getattr(normalized_rule, 'custom_fields_data', None)
                        if cfd:
                            custom_fields = json.loads(cfd) if isinstance(cfd, str) else cfd
                            # Try exact field name and de-prefixed variant
                            if isinstance(custom_fields, dict):
                                field_value = custom_fields.get(field_name)
                                if field_value is None and field_name.startswith('custom_'):
                                    field_value = custom_fields.get(field_name[7:])
                                # Dynamic service_count if requested but missing
                                if field_value is None and field_name in ('service_count','custom_service_count'):
                                    try:
                                        sp = str(getattr(normalized_rule, 'service_port', '') or '')
                                        dp = str(getattr(normalized_rule, 'dest_port', '') or '')
                                        app_raw = str(getattr(normalized_rule, 'application', '') or '')
                                        combined = f"{sp} {dp}".strip()
                                        if not combined:
                                            field_value = 0
                                        else:
                                            # import re (already imported at module level)
                                            raw_tokens = re.split(r"[;\,\|\s/]+", combined)
                                            raw_tokens = [t for t in raw_tokens if t]
                                            ports_seen = set()
                                            app_tokens = [t.strip().lower() for t in re.split(r"[;\,\|\s/]+", app_raw) if t.strip()]
                                            app_tokens = [t for t in app_tokens if t not in ('any','all','*')]
                                            app_count = len(dict.fromkeys(app_tokens))
                                            count = 0
                                            for t in raw_tokens:
                                                tl = t.strip().lower()
                                                if not tl:
                                                    continue
                                                if tl in ('any', 'all', '*'):
                                                    count += 65535
                                                    continue
                                                m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", tl)
                                                if m:
                                                    try:
                                                        start = int(m.group(1))
                                                        end = int(m.group(2))
                                                        if end >= start:
                                                            count += (end - start + 1)
                                                        else:
                                                            count += 1
                                                    except Exception:
                                                        count += 1
                                                    continue
                                                m2 = re.fullmatch(r"(?:tcp|udp|icmp|ip)[_\-:/]?([0-9]+)", tl)
                                                if m2:
                                                    p = m2.group(1)
                                                    if p not in ports_seen:
                                                        ports_seen.add(p)
                                                        count += 1
                                                    continue
                                                if re.fullmatch(r"\d+", tl):
                                                    if tl not in ports_seen:
                                                        ports_seen.add(tl)
                                                        count += 1
                                                    continue
                                                # ignore non-port tokens here
                                            field_value = count
                                    except Exception:
                                        field_value = 0
                    except Exception:
                        field_value = None
        
            # Aggregate service/application tokens for service-related fields
            try:
                if field_name in ('service_port','dest_port','service_name','service'):
                    sp = str(getattr(normalized_rule, 'service_port', '') or '')
                    dp = str(getattr(normalized_rule, 'dest_port', '') or '')
                    sn = str(getattr(normalized_rule, 'service_name', '') or '')
                    # Also include application field as requested by user
                    app_val = str(getattr(normalized_rule, 'application', '') or '')
                    
                    combined = f"{sp} {dp} {sn} {app_val}".strip()
                    if combined:
                        # import re (already imported at module level)
                        raw_tokens = re.split(r"[;\,\|\s/]+", combined)
                        raw_tokens = [t for t in raw_tokens if t]
                        seen = set()
                        out = []
                        for t in raw_tokens:
                            tl = t.strip()
                            if not tl:
                                continue
                            if tl.lower() in ('any','all','*'):
                                out.append(tl)
                                continue
                            if tl not in seen:
                                seen.add(tl)
                                out.append(tl)
                        field_value = '; '.join(out)
            except Exception:
                pass
            
            # Convert to string for comparison
            field_value_str = str(field_value) if field_value is not None else ""
            
            # Get the operator function
            operator_func = self.operators.get(compliance_rule.operator)
            if not operator_func:
                logger.error(f"Unknown operator: {compliance_rule.operator}")
                return {
                    'compliant': False,
                    'violation_details': f"Unknown operator: {compliance_rule.operator}",
                    'field_value': field_value_str,
                    'expected_value': compliance_rule.value,
                    'operator': compliance_rule.operator
                }
            
            match = operator_func(field_value_str, compliance_rule.value)
            if self.violation_mode:
                is_compliant = not match
                violation_details = None if is_compliant else (
                    f"Violation: field '{compliance_rule.field_to_check}' with value '{field_value_str}' "
                    f"matched '{compliance_rule.operator}' condition '{compliance_rule.value}'"
                )
            else:
                is_compliant = match
                violation_details = None if is_compliant else (
                    f"Field '{compliance_rule.field_to_check}' with value '{field_value_str}' "
                    f"does not satisfy '{compliance_rule.operator}' condition with '{compliance_rule.value}'"
                )
            
            return {
                'compliant': is_compliant,
                'violation_details': violation_details,
                'field_value': field_value_str,
                'expected_value': compliance_rule.value,
                'operator': compliance_rule.operator
            }
            
        except Exception as e:
            logger.error(f"Error evaluating compliance rule {compliance_rule.id}: {str(e)}")
            return {
                'compliant': False,
                'violation_details': f"Evaluation error: {str(e)}",
                'field_value': str(field_value) if 'field_value' in locals() else "unknown",
                'expected_value': compliance_rule.value,
                'operator': compliance_rule.operator
            }

    def _eval_condition_group(self, normalized_rule: NormalizedRule, group: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        logic = (group.get('logic') or 'AND').upper()
        failures: List[Dict[str, Any]] = []
        def eval_condition(cond: Dict[str, Any]) -> bool:
            negate = bool(cond.get('not'))
            if 'conditions' in cond and isinstance(cond.get('conditions'), list):
                ok, fails = self._eval_condition_group(normalized_rule, cond)
                if negate:
                    ok = not ok
                if not ok:
                    failures.extend(fails)
                return ok
            field = cond.get('field') or ''
            operator = cond.get('operator') or ''
            value = cond.get('value') or ''
            fv = ''
            # Resolve field value similar to main evaluation
            try:
                if str(field).startswith('custom_'):
                    custom_field_name = str(field)[7:]
                    if normalized_rule.custom_fields_data:
                        custom_fields = json.loads(normalized_rule.custom_fields_data)
                        fv = str(custom_fields.get(custom_field_name) or '')
                else:
                    base = getattr(normalized_rule, field, None)
                    if base is None and field in ('rule_text','raw_text'):
                        raw = getattr(normalized_rule, 'raw_rule', None)
                        if raw is not None:
                            base = getattr(raw, field, None)
                    fv = str(base or '')
                try:
                    if field in ('service_port', 'dest_port', 'service_name', 'service'):
                        sp = str(getattr(normalized_rule, 'service_port', '') or '')
                        dp = str(getattr(normalized_rule, 'dest_port', '') or '')
                        sn = str(getattr(normalized_rule, 'service_name', '') or '')
                        # Include application field
                        app_val = str(getattr(normalized_rule, 'application', '') or '')
                        combined = f"{sp} {dp} {sn} {app_val}".strip()
                        if combined:
                            raw_tokens = re.split(r"[;,\s/|]+", combined)
                            raw_tokens = [t for t in raw_tokens if t]
                            seen = set()
                            out = []
                            for t in raw_tokens:
                                tl = t.strip()
                                if not tl:
                                    continue
                                if tl.lower() in ('any', 'all', '*'):
                                    out.append(tl)
                                    continue
                                if tl not in seen:
                                    seen.add(tl)
                                    out.append(tl)
                            fv = '; '.join(out)
                except Exception:
                    pass
                func = self.operators.get(operator)
                ok = bool(func(fv, str(value))) if func else False
                
                # Debug logging for Rule 50
                # if '22,3389' in str(value) or 'citrix' in str(value):
                #     logger.info(f"Eval Condition: Field={field} Val={ascii(fv)} Op={ascii(operator)} RuleVal={value} Result={ok}")
                #     logger.info(f"Func: {func} Name: {getattr(func, '__name__', 'unknown')}")
                #     if func is None:
                #         logger.info(f"Available Operators: {list(self.operators.keys())}")
                #     if not ok and 'citrix' in str(value):
                #          logger.info(f"RE Module: {re.__file__}")
                #          # Test locally
                #          m = re.search(str(value), fv, re.IGNORECASE)
                #          logger.info(f"Local Match: {m}")

                if negate:
                    ok = not ok
                if not ok:
                    failures.append({'field': field, 'operator': operator, 'value': value, 'field_value': fv, 'not': negate})
                return ok
            except Exception as e:
                failures.append({'field': field, 'operator': operator, 'value': value, 'error': str(e)})
                return False

        conds = group.get('conditions') or []
        if logic == 'AND':
            all_ok = True
            for c in conds:
                if not eval_condition(c):
                    all_ok = False
            return all_ok, failures
        elif logic == 'OR':
            any_ok = False
            for c in conds:
                if eval_condition(c):
                    any_ok = True
                else:
                    # collect failure for visibility; if any_ok ends true, failures can be ignored
                    pass
            if not any_ok and not failures:
                failures.append({'group_logic': 'OR', 'message': 'No conditions satisfied'})
            return any_ok, failures
        else:
            # Default AND
            all_ok = True
            for c in conds:
                if not eval_condition(c):
                    all_ok = False
            return all_ok, failures
    
    def evaluate_rule_against_profile(self, normalized_rule: NormalizedRule, 
                                    profile: ReviewProfile) -> Dict[str, Any]:
        """
        Evaluate a normalized rule against all compliance rules in a profile
        
        Returns:
            dict: {
                'profile_compliant': bool,
                'total_rules': int,
                'passed_rules': int,
                'failed_rules': int,
                'violations': List[dict],
                'compliance_score': float  # percentage of rules passed
            }
        """
        try:
            # Get all rule links for this profile
            rule_links = ProfileRuleLink.query.filter_by(
                profile_id=profile.id
            ).join(ComplianceRule).filter(
                ComplianceRule.is_active == True
            ).all()
            
            if not rule_links:
                return {
                    'profile_compliant': True,
                    'total_rules': 0,
                    'passed_rules': 0,
                    'failed_rules': 0,
                    'violations': [],
                    'compliance_score': 100.0
                }

            # Treat explicit deny/drop/block actions as compliant regardless of fields
            action = str(getattr(normalized_rule, 'action', '') or '').strip().lower()
            if action in ('deny', 'block', 'drop'):
                return {
                    'profile_compliant': True,
                    'total_rules': len(rule_links),
                    'passed_rules': len(rule_links),
                    'failed_rules': 0,
                    'violations': [],
                    'compliance_score': 100.0
                }
            
            violations = []
            passed_count = 0
            failed_count = 0
            
            for link in rule_links:
                compliance_rule = link.rule
                evaluation = self.evaluate_rule_against_compliance(normalized_rule, compliance_rule)
                
                if evaluation['compliant']:
                    passed_count += 1
                else:
                    failed_count += 1
                    violations.append({
                        'rule_id': compliance_rule.id,
                        'rule_name': compliance_rule.rule_name,
                        'severity': compliance_rule.severity,
                        'is_mandatory': link.is_mandatory,
                        'weight': link.weight,
                        'violation_details': evaluation['violation_details'],
                        'field_checked': compliance_rule.field_to_check,
                        'field_value': evaluation['field_value'],
                        'expected_value': evaluation['expected_value'],
                        'operator': evaluation['operator']
                    })
            
            total_rules = len(rule_links)
            compliance_score = (passed_count / total_rules * 100) if total_rules > 0 else 100.0
            
            # Profile is compliant if all mandatory rules pass
            mandatory_violations = [v for v in violations if v['is_mandatory']]
            profile_compliant = len(mandatory_violations) == 0
            
            return {
                'profile_compliant': profile_compliant,
                'total_rules': total_rules,
                'passed_rules': passed_count,
                'failed_rules': failed_count,
                'violations': violations,
                'compliance_score': compliance_score
            }
            
        except Exception as e:
            logger.error(f"Error evaluating profile {profile.id}: {str(e)}")
            return {
                'profile_compliant': False,
                'total_rules': 0,
                'passed_rules': 0,
                'failed_rules': 0,
                'violations': [{'error': f"Evaluation error: {str(e)}"}],
                'compliance_score': 0.0
            }
    
    def evaluate_all_rules_against_profile(self, profile_id: int, 
                                         limit: int = None) -> Dict[str, Any]:
        """
        Evaluate all normalized rules against a specific profile
        
        Returns:
            dict: {
                'profile_info': dict,
                'total_normalized_rules': int,
                'compliant_rules': int,
                'non_compliant_rules': int,
                'overall_compliance_score': float,
                'rule_evaluations': List[dict]
            }
        """
        try:
            # Get the profile
            profile = ReviewProfile.query.get(profile_id)
            if not profile:
                raise ValueError(f"Profile {profile_id} not found")
            
            # Get normalized rules (not deleted)
            query = NormalizedRule.query.filter_by(is_deleted=False)
            if limit:
                query = query.limit(limit)
            
            normalized_rules = query.all()
            
            rule_evaluations = []
            compliant_count = 0
            non_compliant_count = 0
            total_score = 0.0
            
            for norm_rule in normalized_rules:
                evaluation = self.evaluate_rule_against_profile(norm_rule, profile)
                
                rule_evaluation = {
                    'normalized_rule_id': norm_rule.id,
                    'source_file': norm_rule.source_file,
                    'action': norm_rule.action,
                    'protocol': norm_rule.protocol,
                    'source_ip': norm_rule.source_ip,
                    'dest_ip': norm_rule.dest_ip,
                    'service_port': norm_rule.service_port,
                    'evaluation': evaluation
                }
                
                rule_evaluations.append(rule_evaluation)
                
                if evaluation['profile_compliant']:
                    compliant_count += 1
                else:
                    non_compliant_count += 1
                
                total_score += evaluation['compliance_score']
            
            total_rules = len(normalized_rules)
            overall_score = (total_score / total_rules) if total_rules > 0 else 100.0
            
            return {
                'profile_info': {
                    'id': profile.id,
                    'name': profile.profile_name,
                    'framework': profile.compliance_framework,
                    'version': profile.version
                },
                'total_normalized_rules': total_rules,
                'compliant_rules': compliant_count,
                'non_compliant_rules': non_compliant_count,
                'overall_compliance_score': overall_score,
                'rule_evaluations': rule_evaluations
            }
            
        except Exception as e:
            logger.error(f"Error evaluating all rules against profile {profile_id}: {str(e)}")
            raise
    
    # Operator implementations
    def _split_list_tokens(self, value: str) -> List[str]:
        parts = re.split(r"[;,\s|]+", str(value or ""))
        return [p.strip() for p in parts if p and str(p).strip()]

    def _parse_port_spec(self, token: str) -> Any:
        s = str(token or "").strip()
        if not s:
            return None
        m = re.search(r"(\d{1,5})\s*-\s*(\d{1,5})", s)
        if m:
            try:
                a = int(m.group(1))
                b = int(m.group(2))
                if a <= b:
                    return (a, b)
                return (b, a)
            except Exception:
                return None
        m2 = re.search(r"\b(\d{1,5})\b", s)
        if m2:
            try:
                p = int(m2.group(1))
                return (p, p)
            except Exception:
                return None
        return None

    def _tokens_match(self, field_token: str, expected_token: str) -> bool:
        ft = str(field_token or "").strip()
        et = str(expected_token or "").strip()
        if not ft or not et:
            return False
        if ft.lower() == et.lower():
            return True
        f_spec = self._parse_port_spec(ft)
        e_spec = self._parse_port_spec(et)
        if f_spec and e_spec:
            return not (f_spec[1] < e_spec[0] or e_spec[1] < f_spec[0])
        return False

    def _equals(self, field_value: str, expected_value: str) -> bool:
        lv = (field_value or "").strip().lower()
        ev = (expected_value or "").strip().lower()
        if ev == 'any':
            if lv in ('any', 'all', '*', '0.0.0.0', '0.0.0.0/0', '::/0', 'ip'):
                return True
            if re.search(r"\b0\.0\.0\.0\b.*\b255\.255\.255\.255\b", lv):
                return True
            if re.fullmatch(r"\s*(0|1)\s*-\s*65535\s*", lv):
                return True
            if 'any' in lv:
                return True
            return False
        if ev in ('allow', 'permit'):
            return lv in ('allow', 'permit')
        if ev in ('deny', 'block'):
            return lv in ('deny', 'block')
        return lv == ev
    
    def _not_equals(self, field_value: str, expected_value: str) -> bool:
        lv = (field_value or "").strip().lower()
        ev = (expected_value or "").strip().lower()
        if ev == 'any':
            if lv in ('any', 'all', '*', '0.0.0.0', '0.0.0.0/0', '::/0', 'ip'):
                return False
            if re.search(r"\b0\.0\.0\.0\b.*\b255\.255\.255\.255\b", lv):
                return False
            if re.fullmatch(r"\s*(0|1)\s*-\s*65535\s*", lv):
                return False
            if 'any' in lv:
                return False
            return True
        if ev in ('allow', 'permit'):
            return lv not in ('allow', 'permit')
        if ev in ('deny', 'block'):
            return lv not in ('deny', 'block')
        return lv != ev
    
    def _contains(self, field_value: str, expected_value: str) -> bool:
        """Check if field value contains any of expected tokens (comma-separated, case-insensitive)"""
        tokens = [t.strip() for t in expected_value.split(',') if t.strip()]
        if not tokens:
            return expected_value.lower() in field_value.lower()
        fv = field_value.lower()
        return any(t.lower() in fv for t in tokens)
    
    def _not_contains(self, field_value: str, expected_value: str) -> bool:
        """Check if field value does not contain any of expected tokens (comma-separated, case-insensitive)"""
        tokens = [t.strip() for t in expected_value.split(',') if t.strip()]
        fv = field_value.lower()
        if not tokens:
            return expected_value.lower() not in fv
        return all(t.lower() not in fv for t in tokens)
    
    def _in_list(self, field_value: str, expected_value: str) -> bool:
        expected_tokens = self._split_list_tokens(expected_value)
        if not expected_tokens:
            return False
        field_tokens = self._split_list_tokens(field_value)
        if not field_tokens:
            field_tokens = [str(field_value or '').strip()]
        for ft in field_tokens:
            for et in expected_tokens:
                if self._tokens_match(ft, et):
                    return True
        return False
    
    def _not_in_list(self, field_value: str, expected_value: str) -> bool:
        return not self._in_list(field_value, expected_value)
    
    def _regex_match(self, field_value: str, expected_value: str) -> bool:
        """Check if field value matches regex pattern"""
        try:
            return bool(re.search(expected_value, field_value, re.IGNORECASE))
        except re.error as e:
            logger.error(f"Invalid regex pattern '{expected_value}': {str(e)}")
            return False

    def _not_regex_match(self, field_value: str, expected_value: str) -> bool:
        """Check if field value does NOT match regex pattern"""
        try:
            match = re.search(expected_value, field_value, re.IGNORECASE)
            return not bool(match)
        except re.error as e:
            logger.error(f"Invalid regex pattern '{expected_value}': {str(e)}")
            # Treat invalid pattern as non-match to avoid false compliance
            return True
    
    def _starts_with(self, field_value: str, expected_value: str) -> bool:
        """Check if field value starts with expected value (case-insensitive)"""
        return field_value.lower().startswith(expected_value.lower())
    
    def _ends_with(self, field_value: str, expected_value: str) -> bool:
        """Check if field value ends with expected value (case-insensitive)"""
        return field_value.lower().endswith(expected_value.lower())
    
    def _is_empty(self, field_value: str, expected_value: str) -> bool:
        """Check if field value is empty or None"""
        try:
            s = str(field_value or "").strip()
            if not s:
                return True
            invalid = {"-", "None", "NA", "N/A"}
            return s in invalid
        except Exception:
            return not field_value or str(field_value).strip() == ""
    
    def _is_not_empty(self, field_value: str, expected_value: str) -> bool:
        """Check if field is not empty"""
        return field_value.strip() != ""
    
    def _greater_than(self, field_value: str, expected_value: str) -> bool:
        """Check if field value is greater than expected value (numeric comparison)"""
        try:
            def _to_float(v):
                if isinstance(v, (int, float)):
                    return float(v)
                s = str(v or '').replace(',', '').strip()
                if not s:
                    return None
                m = re.search(r"[-+]?\d+(?:\.\d+)?", s)
                if m:
                    try:
                        return float(m.group(0))
                    except Exception:
                        return None
                return None
            fv = _to_float(field_value)
            ev = _to_float(expected_value)
            if fv is None or ev is None:
                return False
            return fv > ev
        except Exception:
            return False
    
    def _greater_than_or_equal(self, field_value: str, expected_value: str) -> bool:
        """Check if field value is greater than or equal to expected value (numeric comparison)"""
        try:
            def _to_float(v):
                if isinstance(v, (int, float)):
                    return float(v)
                s = str(v or '').replace(',', '').strip()
                if not s:
                    return None
                m = re.search(r"[-+]?\d+(?:\.\d+)?", s)
                if m:
                    try:
                        return float(m.group(0))
                    except Exception:
                        return None
                return None
            fv = _to_float(field_value)
            ev = _to_float(expected_value)
            if fv is None or ev is None:
                return False
            return fv >= ev
        except Exception:
            return False
    
    def _less_than(self, field_value: str, expected_value: str) -> bool:
        """Check if field value is less than expected value (numeric comparison)"""
        try:
            def _to_float(v):
                if isinstance(v, (int, float)):
                    return float(v)
                s = str(v or '').replace(',', '').strip()
                if not s:
                    return None
                m = re.search(r"[-+]?\d+(?:\.\d+)?", s)
                if m:
                    try:
                        return float(m.group(0))
                    except Exception:
                        return None
                return None
            fv = _to_float(field_value)
            ev = _to_float(expected_value)
            if fv is None or ev is None:
                return False
            return fv < ev
        except Exception:
            return False
    
    def _less_than_or_equal(self, field_value: str, expected_value: str) -> bool:
        """Check if field value is less than or equal to expected value (numeric comparison)"""
        try:
            def _to_float(v):
                if isinstance(v, (int, float)):
                    return float(v)
                s = str(v or '').replace(',', '').strip()
                if not s:
                    return None
                m = re.search(r"[-+]?\d+(?:\.\d+)?", s)
                if m:
                    try:
                        return float(m.group(0))
                    except Exception:
                        return None
                return None
            fv = _to_float(field_value)
            ev = _to_float(expected_value)
            if fv is None or ev is None:
                return False
            return fv <= ev
        except Exception:
            return False


# Global instance
compliance_engine = ComplianceEngine()


def get_available_fields() -> List[Dict[str, str]]:
    """
    Get all available fields from NormalizedRule model and custom fields
    
    Returns:
        List of dicts with field info: [{'name': 'field_name', 'type': 'field_type', 'description': '...'}]
    """
    fields = []
    
    # Define field descriptions for better UX
    field_descriptions = {
        'action': 'Rule action (permit, deny)',
        'protocol': 'Network protocol (tcp, udp, icmp, ip)',
        'source_zone': 'Source zone name from policy',
        'source_ip': 'Source IP address',
        'source_port': 'Source port number or range',
        'source_hostname': 'Source hostname from CMDB',
        'source_owner': 'Source asset owner from CMDB',
        'source_department': 'Source department from CMDB',
        'source_environment': 'Source environment (prod, staging, dev)',
        'source_vlan_id': 'Source VLAN ID',
        'source_vlan_name': 'Source VLAN name',
        'source_subnet': 'Source subnet in CIDR notation',
        'application': 'Application name for the rule',
        'dest_ip': 'Destination IP address',
        'dest_port': 'Destination port number or range',
        'dest_hostname': 'Destination hostname from CMDB',
        'dest_owner': 'Destination asset owner from CMDB',
        'dest_department': 'Destination department from CMDB',
        'dest_environment': 'Destination environment (prod, staging, dev)',
        'dest_vlan_id': 'Destination VLAN ID',
        'dest_vlan_name': 'Destination VLAN name',
        'dest_subnet': 'Destination subnet in CIDR notation',
        'dest_zone': 'Destination zone name from policy',
        'service_name': 'Service name',
        'service_port': 'Service port (e.g., TCP/80, UDP/53)',
        'service_protocol': 'Service protocol',
        'is_disabled': 'Whether the rule is disabled/inactive',
        'risk_level': 'Risk level (low, medium, high, critical)',
        'compliance_status': 'Compliance status (compliant, non_compliant, needs_review)',
        'review_status': 'Review status (pending, approved, rejected)',
        'source_file': 'Original configuration file name'
    }
    
    # Get column info from the model
    for column in NormalizedRule.__table__.columns:
        field_name = column.name
        
        # Skip internal fields
        if field_name in ['id', 'raw_rule_id', 'normalization_date', 'created_at', 'updated_at', 'is_deleted', 'custom_fields_data']:
            continue
        
        field_type = str(column.type)
        description = field_descriptions.get(field_name, f"Field: {field_name}")
        
        fields.append({
            'name': field_name,
            'type': field_type,
            'description': description
        })
    
    # Add synthetic raw fields
    fields.append({'name':'rule_text','type':'Text','description':'Raw rule text (from original config)'});
    fields.append({'name':'raw_text','type':'Text','description':'Raw rule text (from original config)'});
    # Add custom fields
    try:
        custom_fields_service = CustomFieldsService()
        custom_fields = custom_fields_service.get_all_fields()
        
        for custom_field in custom_fields:
            fields.append({
                'name': f"custom_{custom_field['field_name']}",
                'type': custom_field['field_type'],
                'description': f"{custom_field['display_name']}: {custom_field.get('description', '')}"
            })
    except Exception as e:
        logger.warning(f"Could not load custom fields: {e}")
    
    return sorted(fields, key=lambda x: x['name'])


def get_available_operators() -> List[Dict[str, str]]:
    """
    Get all available operators for compliance rules
    
    Returns:
        List of dicts with operator info: [{'name': 'operator_name', 'description': '...'}]
    """
    return [
        {'name': 'composite', 'description': 'Advanced: JSON condition group with AND/OR/NOT across multiple fields'},
        {'name': 'equals', 'description': 'Field value equals the specified value (case-insensitive)'},
        {'name': 'not_equals', 'description': 'Field value does not equal the specified value (case-insensitive)'},
        {'name': 'contains', 'description': 'Field value contains the specified text (case-insensitive)'},
        {'name': 'not_contains', 'description': 'Field value does not contain the specified text (case-insensitive)'},
        {'name': 'in_list', 'description': 'Field value is in comma-separated list (case-insensitive)'},
        {'name': 'not_in_list', 'description': 'Field value is not in comma-separated list (case-insensitive)'},
        {'name': 'regex_match', 'description': 'Field value matches regular expression pattern'},
        {'name': 'not_regex_match', 'description': 'Field value does not match regular expression pattern'},
        {'name': 'starts_with', 'description': 'Field value starts with the specified text (case-insensitive)'},
        {'name': 'ends_with', 'description': 'Field value ends with the specified text (case-insensitive)'},
        {'name': 'is_empty', 'description': 'Field value is empty or null'},
        {'name': 'is_not_empty', 'description': 'Field value is not empty'},
        {'name': 'greater_than', 'description': 'Numeric: value > expected'},
        {'name': 'greater_than_or_equal', 'description': 'Numeric: value >= expected'},
        {'name': 'less_than', 'description': 'Numeric: value < expected'},
        {'name': 'less_than_or_equal', 'description': 'Numeric: value <= expected'}
    ]
