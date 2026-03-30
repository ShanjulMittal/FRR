"""
Rule Normalizer

This script processes raw firewall rules by expanding object groups and enriching
them with CMDB and VLAN data to create normalized rules for analysis.
"""

import logging
import ipaddress
import re
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from models import (
    RawFirewallRule, ObjectGroup, ObjectGroupMember, NormalizedRule,
    CMDBAsset, VLANNetwork, db
)
from custom_fields_service import CustomFieldsService
from protocol_port_parser import parse_protocol_port, parse_service_field, SERVICE_MAPPING_API_BASE, get_service_name_for_port
import requests
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleNormalizer:
    """Normalizes firewall rules by expanding object groups and enriching with CMDB/VLAN data"""
    
    def __init__(self, expand_services: bool = False, group_by_remark: bool = False):
        self.stats = {
            'rules_processed': 0,
            'normalized_rules_created': 0,
            'object_groups_expanded': 0,
            'cmdb_matches': 0,
            'vlan_matches': 0,
            'errors': 0
        }
        self.expand_services = expand_services
        self.group_by_remark = group_by_remark
        # Initialize custom fields service
        self.custom_fields_service = CustomFieldsService()
    
    def get_object_group_members(self, group_name: str, silent: bool = False) -> List[str]:
        try:
            # Strip "object-group" prefix if present
            clean_group_name = group_name
            if isinstance(group_name, str):
                gl = group_name.strip().lower()
                if gl.startswith("object-group "):
                    clean_group_name = group_name[13:].strip()
                elif gl.startswith("object "):
                    clean_group_name = group_name[7:].strip()
            
            object_groups = db.session.query(ObjectGroup).filter_by(name=clean_group_name).all()
            if not object_groups:
                try:
                    base = clean_group_name.strip()
                    alt_names = []
                    alt_names.append(base.replace('-', '_'))
                    alt_names.append(base.replace('_', '-'))
                    for token in ['infra', 'subnet', 'subnets', 'group', 'grp']:
                        if base.lower().endswith(f"-{token}") or base.lower().endswith(f"_{token}"):
                            alt_names.append(re.sub(r"[-_]" + token + r"$", "", base, flags=re.IGNORECASE))
                    for an in alt_names:
                        if an and an != base:
                            res = db.session.query(ObjectGroup).filter_by(name=an).all()
                            if res:
                                object_groups = res
                                break
                except Exception:
                    pass
                if not object_groups:
                    if not silent:
                        logger.warning(f"Object group '{clean_group_name}' not found")
                    return []
            
            members = []
            for og in object_groups:
                members.extend(db.session.query(ObjectGroupMember).filter_by(object_group_id=og.id).all())
            member_values = []
            if members:
                for member in members:
                    if member.member_type in ('ip','subnet','range','service','host','port'):
                        member_values.append(member.member_value)
            else:
                try:
                    raw_members = []
                    for og in object_groups:
                        if og.members:
                            try:
                                raw_members.extend(json.loads(og.members))
                            except Exception:
                                pass
                except Exception:
                    raw_members = []
                for m in raw_members:
                    if isinstance(m, dict):
                        t = m.get('type')
                        if t in ('host','network'):
                            addr = m.get('address')
                            mask = m.get('mask')
                            if addr:
                                member_values.append(addr if t == 'host' else (f"{addr} {mask}" if mask else addr))
                        elif t == 'range':
                            addr = m.get('address')
                            if addr:
                                member_values.append(str(addr))
                        else:
                            proto = m.get('protocol')
                            port = m.get('port')
                            if port and str(port).isdigit():
                                member_values.append(f"{proto}/{port}" if proto else str(port))
                            elif port:
                                member_values.append(str(port))
                            elif proto:
                                member_values.append(str(proto))
                    else:
                        if m:
                            member_values.append(str(m))
            # Normalize tcp-udp tokens into tcp and udp
            normalized_values = []
            for mv in member_values:
                s = str(mv)
                if s.lower().startswith('tcp-udp/'):
                    normalized_values.append('tcp/' + s.split('/',1)[1])
                    normalized_values.append('udp/' + s.split('/',1)[1])
                else:
                    normalized_values.append(s)
            # Drop ambiguous '*/range' tokens when clearer numeric ranges exist
            has_numeric_range = any(re.search(r"/\d+\-\d+$", v) for v in normalized_values)
            filtered_values = []
            for v in normalized_values:
                lv = v.lower()
                if has_numeric_range and (lv.endswith('/range') or re.search(r"/range(\b|$)", lv)):
                    continue
                filtered_values.append(v)
            return filtered_values
        
        except Exception as e:
            logger.error(f"Error getting members for group '{group_name}': {str(e)}")
            return []
    
    def is_object_group(self, value: str) -> bool:
        """Check if a value is an object group reference"""
        if not value:
            return False
        
        # Direct ASA-style prefix
        if isinstance(value, str) and (value.strip().lower().startswith('object-group ') or value.strip().lower().startswith('object ')):
            return True
        # Check against common object group patterns
        object_group_indicators = [
            'OBJ-', 'GRP-', '-OBJ', '-GRP', 'GROUP_', '-GROUP',
            'NET-', 'SVC-', 'HOST-'
        ]
        
        value_upper = value.upper()
        return any(indicator in value_upper for indicator in object_group_indicators)
    
    def expand_object_group_field(self, field_value: str) -> List[str]:
        """Expand a field that might contain object groups"""
        if not field_value:
            return ['']
        # Handle multiple tokens separated by common delimiters
        tokens = [t.strip() for t in re.split(r"[;,]", str(field_value)) if t.strip()] or [str(field_value).strip()]
        expanded: List[str] = []
        def _to_cidr_if_masked(val: str) -> str:
            try:
                # Match "IP MASK" (e.g., 172.18.209.128 255.255.255.128)
                m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$", val.strip())
                if m:
                    ip = m.group(1)
                    mask = m.group(2)
                    ipaddress.ip_address(ip)
                    # Convert netmask to prefix length
                    parts = [int(p) for p in mask.split('.')]
                    if all(0 <= p <= 255 for p in parts):
                        # Build integer mask and count bits
                        mask_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
                        # Validate contiguous mask (optional)
                        prefix = bin(mask_int).count('1')
                        if prefix >= 0 and prefix <= 32:
                            return f"{ip}/{prefix}"
                return val
            except Exception:
                return val
        for tok in tokens:
            tl = tok.lower()
            if tl in ('destination', 'service'):
                # Skip parser artifacts
                continue
            if tl.startswith('host '):
                ipval = tok.split(' ', 1)[1].strip()
                expanded.append(_to_cidr_if_masked(ipval))
                continue
            m_range = re.search(r"\brange\s+((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})", tok)
            if m_range:
                start_ip = m_range.group(1)
                end_ip = m_range.group(2)
                expanded.append(f"{start_ip}-{end_ip}")
                continue
            if tl.startswith('object-group '):
                name = tok.split(' ', 1)[1].strip()
                members = self.get_object_group_members(name)
                if members:
                    self.stats['object_groups_expanded'] += 1
                    for m in members:
                        if not m:
                            continue
                        sub = self.expand_object_group_field(str(m))
                        if sub:
                            expanded.extend([_to_cidr_if_masked(s) for s in sub if s])
                        else:
                            expanded.append(_to_cidr_if_masked(str(m)))
                else:
                    expanded.append(tok)
                continue
            if tl.startswith('object '):
                name = tok.split(' ', 1)[1].strip()
                # Heuristic: host object named like H_<ip>
                if re.match(r'(?i)^H_\d{1,3}(?:\.\d{1,3}){3}$', name):
                    ip = name.split('_', 1)[1]
                    expanded.append(_to_cidr_if_masked(ip))
                    continue
                # Heuristic: range object named like R_<ip>-<ip> or R_<ip>_<ip>
                m_range = re.match(r'(?i)^R_(\d{1,3}(?:\.\d{1,3}){3})[-_](\d{1,3}(?:\.\d{1,3}){3})$', name)
                if m_range:
                    start_ip = m_range.group(1)
                    end_ip = m_range.group(2)
                    expanded.append(f"{start_ip}-{end_ip}")
                    continue
                # Heuristic: compressed last-octet range like R_<a.b.c.dStart>-<dEnd>
                m_last_octet = re.match(r'(?i)^R_((?:\d{1,3}\.){3})(\d{1,3})[-_](\d{1,3})$', name)
                if m_last_octet:
                    prefix = m_last_octet.group(1)
                    d_start = m_last_octet.group(2)
                    d_end = m_last_octet.group(3)
                    start_ip = f"{prefix}{d_start}"
                    end_ip = f"{prefix}{d_end}"
                    expanded.append(f"{start_ip}-{end_ip}")
                    continue
                members = self.get_object_group_members(name)
                if members:
                    self.stats['object_groups_expanded'] += 1
                    for m in members:
                        if not m:
                            continue
                        sub = self.expand_object_group_field(str(m))
                        if sub:
                            expanded.extend([_to_cidr_if_masked(s) for s in sub if s])
                        else:
                            expanded.append(_to_cidr_if_masked(str(m)))
                else:
                    expanded.append(tok)
                continue
            # Check if it is an object group either by syntax or by lookup
            is_group = self.is_object_group(tok)
            members = []
            
            if is_group:
                members = self.get_object_group_members(tok)
            elif not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?$", tok) and tok.lower() != 'any':
                # Try lookup even if not explicit object-group syntax
                members = self.get_object_group_members(tok, silent=True)
            
            if members:
                self.stats['object_groups_expanded'] += 1
                for m in members:
                    if not m:
                        continue
                    sub = self.expand_object_group_field(str(m))
                    if sub:
                        expanded.extend([_to_cidr_if_masked(s) for s in sub if s])
                    else:
                        expanded.append(_to_cidr_if_masked(str(m)))
            else:
                expanded.append(_to_cidr_if_masked(tok))
        return expanded

    def expand_from_raw_details(self, raw_rule: RawFirewallRule) -> Tuple[Optional[str], Optional[str]]:
        try:
            rt = getattr(raw_rule, 'raw_text', None)
            if not rt:
                return None, None
            parsed = None
            try:
                parsed = json.loads(rt)
            except Exception:
                parsed = None
            if not isinstance(parsed, dict):
                return None, None
            details = parsed.get('details') or []
            if not isinstance(details, list) or not details:
                return None, None
            def _to_cidr_if_masked(val: str) -> str:
                try:
                    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$", str(val).strip())
                    if m:
                        ip = m.group(1)
                        mask = m.group(2)
                        ipaddress.ip_address(ip)
                        parts = [int(p) for p in mask.split('.')]
                        if all(0 <= p <= 255 for p in parts):
                            mask_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
                            prefix = bin(mask_int).count('1')
                            if 0 <= prefix <= 32:
                                return f"{ip}/{prefix}"
                    return str(val)
                except Exception:
                    return str(val)
            def _extract_range_token(text: str) -> Optional[str]:
                try:
                    if not text:
                        return None
                    m = re.search(r"\brange\s+((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})", text)
                    if m:
                        a = m.group(1).strip()
                        b = m.group(2).strip()
                        return f"{a}-{b}"
                except Exception:
                    return None
                return None
            src_tokens: List[str] = []
            dst_tokens: List[str] = []
            seen_s = set()
            seen_d = set()
            for d in details:
                try:
                    s = (d.get('source') if isinstance(d, dict) else None) or ''
                    dl = (d.get('destination') if isinstance(d, dict) else None) or ''
                except Exception:
                    s = ''
                    dl = ''
                s2 = str(s).strip()
                dl2 = str(dl).strip()
                if s2.lower().startswith('host '):
                    s2 = s2.split(' ', 1)[1].strip()
                if dl2.lower().startswith('host '):
                    dl2 = dl2.split(' ', 1)[1].strip()
                s_range_token = None
                d_range_token = None
                try:
                    s_range_token = _extract_range_token(str(d.get('raw_text') or '')) if s2.lower().startswith('range') or s2.lower() == 'range' else None
                    d_range_token = _extract_range_token(str(d.get('raw_text') or '')) if dl2.lower().startswith('range') or dl2.lower() == 'range' else None
                except Exception:
                    s_range_token = None
                    d_range_token = None
                s2 = s_range_token or _to_cidr_if_masked(s2)
                dl2 = d_range_token or _to_cidr_if_masked(dl2)
                if s2 and s2 not in seen_s:
                    seen_s.add(s2)
                    src_tokens.append(s2)
                if dl2 and dl2 not in seen_d:
                    seen_d.add(dl2)
                    dst_tokens.append(dl2)
            src_str = ';'.join(src_tokens) if src_tokens else None
            dst_str = ';'.join(dst_tokens) if dst_tokens else None
            return src_str, dst_str
        except Exception:
            return None, None

    def upsert_virtual_object_group(self, group_name: str, member_tokens: List[str], source_file: Optional[str] = None, vendor: Optional[str] = 'cisco_asa') -> None:
        try:
            if not group_name:
                return
            # Clean ASA prefixes
            gl = group_name.strip().lower()
            if gl.startswith('object-group '):
                group_name = group_name[13:].strip()
            elif gl.startswith('object '):
                group_name = group_name[7:].strip()
            group = db.session.query(ObjectGroup).filter_by(name=group_name).first()
            created = False
            if not group:
                group = ObjectGroup(
                    source_file=str(source_file or 'virtual'),
                    file_line_number=None,
                    name=group_name,
                    group_type='network',
                    protocol=None,
                    vendor=str(vendor or 'auto'),
                    description='Virtual object-group derived from ACL details',
                    members=json.dumps(member_tokens),
                    status='resolved'
                )
                db.session.add(group)
                db.session.flush()
                created = True
            else:
                # Merge members into JSON blob for quick preview
                try:
                    existing = json.loads(group.members) if group.members else []
                except Exception:
                    existing = []
                sset = {str(x) for x in existing}
                for t in member_tokens:
                    if str(t) not in sset:
                        existing.append(str(t))
                        sset.add(str(t))
                group.members = json.dumps(existing)
                group.status = 'resolved'
            # Upsert detailed members
            for tok in member_tokens:
                val = str(tok).strip()
                if not val:
                    continue
                # Normalize masked IP to CIDR for member_type decision but store original val
                member_type = 'host'
                m_mask = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$", val)
                if m_mask:
                    member_type = 'subnet'
                elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", val):
                    member_type = 'subnet'
                else:
                    # pure IPv4 literal
                    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", val):
                        member_type = 'host'
                    else:
                        member_type = 'unknown'
                exists = db.session.query(ObjectGroupMember).filter_by(object_group_id=group.id, member_value=val).first()
                if not exists:
                    db.session.add(ObjectGroupMember(
                        object_group_id=group.id,
                        member_type=member_type,
                        member_value=val,
                        description='Derived from ACL details'
                    ))
            if created:
                logger.info(f"Created virtual object-group '{group_name}' with {len(member_tokens)} members")
            db.session.commit()
        except Exception as e:
            logger.error(f"Error upserting virtual object group '{group_name}': {str(e)}")
            db.session.rollback()
            
    def extract_group_names_from_field(self, field_value: str) -> List[str]:
        try:
            if not field_value:
                return []
            text = str(field_value)
            names = []
            # Prefer ASA object-group/network/service patterns
            for m in re.finditer(r"\bobject-group\s+(?:network|service)?\s*([A-Za-z0-9_\-]+)\b", text, flags=re.IGNORECASE):
                names.append(m.group(1))
            for m in re.finditer(r"\bobject\s+([A-Za-z0-9_\-\.]+)\b", text, flags=re.IGNORECASE):
                # Avoid matching 'object-group' again
                token = m.group(1)
                if token.lower().startswith('group'):
                    continue
                names.append(token)
            # Fallback single token after literal 'object-group'
            if not names:
                m = re.search(r"\bobject-group\s+([A-Za-z0-9_\-]+)\b", text, flags=re.IGNORECASE)
                if m:
                    names.append(m.group(1))
            # Deduplicate while preserving order
            out = []
            seen = set()
            for n in names:
                if n not in seen:
                    seen.add(n)
                    out.append(n)
            return out
        except Exception:
            return []

    def _expand_service_object_groups(self, service_tokens: str) -> str:
        """
        Expand service field tokens that include object-group references into concrete protocol/port tokens.
        Returns a semicolon-separated string of expanded tokens.
        """
        if not service_tokens:
            return ''
        parts = [p.strip() for p in str(service_tokens).split(';') if p.strip()]
        expanded: List[str] = []
        for tok in parts:
            if tok.lower().startswith('object-group'):
                grp = tok.split(' ', 1)[1].strip() if ' ' in tok else tok
                members = self.get_object_group_members(grp)
                if members:
                    # Heuristic: fix known SNMP range tokens
                    if grp and 'snmp' in grp.strip().lower():
                        fixed_members = []
                        for m in members:
                            s = str(m).strip().lower()
                            if s.endswith('/range'):
                                if s.startswith('tcp/'):
                                    fixed_members.append('tcp/161-162')
                                elif s.startswith('udp/'):
                                    fixed_members.append('udp/161-162')
                                else:
                                    fixed_members.append(m)
                            else:
                                fixed_members.append(m)
                        members = fixed_members
                    for m in members:
                        if not m:
                            continue
                        ml = str(m).strip().lower()
                        if ml in ('destination','service'):
                            continue
                        expanded.append(str(m))
                else:
                    expanded.append(tok)
            elif tok.lower().startswith('object '):
                grp = tok.split(' ', 1)[1].strip() if ' ' in tok else tok
                members = self.get_object_group_members(grp)
                if members:
                    for m in members:
                        if not m:
                            continue
                        ml = str(m).strip().lower()
                        if ml in ('destination','service'):
                            continue
                        expanded.append(str(m))
                else:
                    expanded.append(tok)
            else:
                # Check if it is an object group either by syntax or by lookup
                is_group = self.is_object_group(tok)
                members = []
                
                if is_group:
                    members = self.get_object_group_members(tok)
                elif not tok.isdigit():
                     tl = tok.strip().lower()
                     if tl not in ('destination', 'service'):
                         members = self.get_object_group_members(tok, silent=True)
                
                if members:
                    for m in members:
                        if not m:
                            continue
                        ml = str(m).strip().lower()
                        if ml in ('destination','service'):
                            continue
                        expanded.append(str(m))
                else:
                    tl = tok.strip().lower()
                    if tl in ('destination','service'):
                        continue
                    expanded.append(tok)
        return ';'.join(expanded)
    
    def lookup_cmdb_asset(self, ip_address: str) -> Optional[CMDBAsset]:
        """Look up CMDB asset information for an IP address"""
        try:
            # Direct IP match
            asset = db.session.query(CMDBAsset).filter_by(ip_address=ip_address).first()
            if asset:
                return asset
            
            # Try to match by hostname if IP is not found
            # This is a fallback in case the CMDB has hostname entries
            return None
            
        except Exception as e:
            logger.error(f"Error looking up CMDB asset for IP '{ip_address}': {str(e)}")
            return None
    
    def lookup_vlan_network(self, ip_address: str) -> Optional[VLANNetwork]:
        """Look up VLAN network information for an IP address"""
        try:
            # Check if IP falls within any VLAN network
            vlans = db.session.query(VLANNetwork).all()
            
            for vlan in vlans:
                try:
                    # Handle multiple subnets separated by space, comma, or newline
                    if not vlan.subnet:
                        continue
                        
                    subnets = re.split(r'[,\s\n]+', str(vlan.subnet).strip())
                    ip = ipaddress.ip_address(ip_address)
                    
                    for subnet_str in subnets:
                        if not subnet_str:
                            continue
                        try:
                            network = ipaddress.ip_network(subnet_str, strict=False)
                            if ip in network:
                                return vlan
                        except (ValueError, ipaddress.AddressValueError):
                            continue
                            
                except Exception:
                    # Skip invalid IP addresses or network CIDRs
                    continue
            
            return None
            
        except Exception as e:
            logger.error(f"Error looking up VLAN for IP '{ip_address}': {str(e)}")
            return None
    
    def enrich_ip_data(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP address with CMDB and VLAN data"""
        enrichment_data = {
            'hostname': None,
            'owner': None,
            'business_unit': None,
            'environment': None,
            'asset_type': None,
            'vlan_id': None,
            'vlan_name': None,
            'network_segment': None,
            'location': None
        }
        
        if not ip_address or ip_address in ['any', 'Any', 'ANY', '0.0.0.0/0']:
            return enrichment_data
        
        # Extract just the IP if it's in CIDR format
        try:
            if '/' in ip_address:
                ip_to_lookup = ip_address.split('/')[0]
            else:
                ip_to_lookup = ip_address
            
            # Validate IP address
            ipaddress.ip_address(ip_to_lookup)
            
        except (ipaddress.AddressValueError, ValueError):
            # Not a valid IP address, return empty enrichment
            return enrichment_data
        
        # Look up CMDB data
        cmdb_asset = self.lookup_cmdb_asset(ip_to_lookup)
        if cmdb_asset:
            enrichment_data.update({
                'hostname': cmdb_asset.hostname,
                'owner': cmdb_asset.owner,
                'business_unit': cmdb_asset.business_unit,
                'environment': cmdb_asset.environment,
                'asset_type': cmdb_asset.asset_type
            })
            self.stats['cmdb_matches'] += 1
        
        # Look up VLAN data
        vlan_network = self.lookup_vlan_network(ip_to_lookup)
        if vlan_network:
            enrichment_data.update({
                'vlan_id': vlan_network.vlan_id,
                'vlan_name': vlan_network.name,
                'network_segment': vlan_network.subnet,
                'location': vlan_network.location
            })
            self.stats['vlan_matches'] += 1
        
        return enrichment_data
    
    def parse_protocol_service_field(self, service_field: str) -> List[Dict[str, Any]]:
        """
        Parse a service field that might contain protocol, port, or both.
        Handles multiple services separated by semicolons or commas.
        
        Args:
            service_field (str): The service field value (e.g., "TCP-80", "SSH;TCP-2202", "HTTPS")
            
        Returns:
            list: List of dictionaries with 'protocol', 'port', and 'service_name' keys
        """
        if not service_field or service_field.strip() in ['', '-', 'None']:
            return [{'protocol': None, 'port': None, 'service_name': service_field}]
        
        # Handle multiple services separated by semicolons OR commas
        normalized = service_field.replace(',', ';')
        services = [s.strip() for s in normalized.split(';') if s.strip()]
        
        if not services:
            return [{'protocol': None, 'port': None, 'service_name': service_field}]
        
        parsed_services = []
        
        for service in services:
            parsed_service = self._parse_single_service(service, service_field)
            if parsed_service:
                parsed_services.append(parsed_service)
        
        # If no services were successfully parsed, return the original
        if not parsed_services:
            return [{'protocol': service_field, 'port': None, 'service_name': service_field}]
        
        return parsed_services
    
    def _parse_single_service(self, service: str, original_field: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single service string to extract protocol and port.
        
        Args:
            service (str): Single service string (e.g., "TCP-80", "HTTPS")
            original_field (str): Original multi-service field for reference
            
        Returns:
            dict or None: Dictionary with protocol, port, and service_name or None if parsing fails
        """
        if not service or service.strip() in ['', '-', 'None']:
            return None
        
        service = service.strip()
        service_lower = service.lower()
        
        # Clean Object Group references
        if service_lower.startswith('object-group '):
            name = service[13:].strip()
            return {
                'protocol': None,
                'port': None,
                'service_name': name
            }
        
        # Check for pure port range: 135-139, 135-netbios-ssn
        # This prevents it being parsed as Protocol-Port (e.g. 135-139 -> Proto:135, Port:139)
        # Matches digit start, followed by hyphen, followed by anything (for named ports)
        if re.match(r'^\d+-[a-zA-Z0-9-]+$', service):
            return {
                'protocol': None,
                'port': service,
                'service_name': service
            }

        # Try to parse using existing protocol_port_parser first
        try:
            parsed = parse_service_field(service)
            if parsed and parsed.get('port'):
                return {
                    'protocol': parsed.get('protocol'),
                    'port': parsed.get('port'),
                    'service_name': parsed.get('service_name') or service
                }
        except Exception:
            pass
        
        service_upper = service.upper()
        # Pattern: PROTOCOL/SERVICE_NAME (e.g., TCP/DOMAIN)
        if '/' in service_upper:
            parts = service_upper.split('/', 1)
            if len(parts) == 2:
                proto_part = parts[0].strip()
                name_part = parts[1].strip()
                if proto_part in ('TCP','UDP','IP') and not name_part.isdigit():
                    try:
                        response = requests.get(f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{name_part}")
                        if response.status_code == 200:
                            service_data = response.json()
                            if service_data and service_data.get('found') and 'mapping' in service_data:
                                mapping = service_data['mapping']
                                return {
                                    'protocol': proto_part,
                                    'port': mapping.get('port_number'),
                                    'service_name': mapping.get('service_name') or name_part
                                }
                    except Exception:
                        pass
                    return {
                        'protocol': proto_part,
                        'port': None,
                        'service_name': name_part
                    }
        
        # Pattern: TCP-port, UDP-port
        if '-' in service_upper:
            parts = service_upper.split('-', 1)
            if len(parts) == 2:
                protocol_part = parts[0].strip()
                port_part = parts[1].strip()
                
                # Handle port ranges like "1521-1523"
                if '-' in port_part and port_part.count('-') == 1:
                    try:
                        start_port, end_port = port_part.split('-')
                        start_port = int(start_port.strip())
                        end_port = int(end_port.strip())
                        # For ranges, use the start port as primary
                        return {
                            'protocol': protocol_part,
                            'port': f"{start_port}-{end_port}",
                            'service_name': f"{protocol_part}-{start_port}-{end_port}"
                        }
                    except ValueError:
                        pass
                
                # Check if the second part is a number (port)
                try:
                    port = int(port_part)
                    return {
                        'protocol': protocol_part,
                        'port': port,
                        'service_name': f"{protocol_part}-{port}"
                    }
                except ValueError:
                    pass
        
        # Pattern: protocol:port
        if ':' in service_upper:
            parts = service_upper.split(':', 1)
            if len(parts) == 2:
                protocol_part = parts[0].strip()
                port_part = parts[1].strip()
                
                try:
                    port = int(port_part)
                    return {
                        'protocol': protocol_part,
                        'port': port,
                        'service_name': f"{protocol_part}-{port}"
                    }
                except ValueError:
                    pass
        
        # Pattern: port/protocol
        if '/' in service_upper:
            parts = service_upper.split('/', 1)
            if len(parts) == 2:
                first_part = parts[0].strip()
                second_part = parts[1].strip()
                
                # Try first part as port, second as protocol
                try:
                    port = int(first_part)
                    return {
                        'protocol': second_part,
                        'port': port,
                        'service_name': f"{second_part}-{port}"
                    }
                except ValueError:
                    # Try first part as protocol, second as port
                    # Handle ranges like PROTOCOL/START-END
                    if '-' in second_part and second_part.count('-') == 1:
                        try:
                            start_port, end_port = second_part.split('-')
                            start_port = int(start_port.strip())
                            end_port = int(end_port.strip())
                            return {
                                'protocol': first_part,
                                'port': f"{start_port}-{end_port}",
                                'service_name': f"{first_part}-{start_port}-{end_port}"
                            }
                        except ValueError:
                            pass
                    try:
                        port = int(second_part)
                        return {
                            'protocol': first_part,
                            'port': port,
                            'service_name': f"{first_part}-{port}"
                        }
                    except ValueError:
                        pass
        
        # Query the service mapping API for well-known services
        try:
            # Try to lookup service by name
            response = requests.get(f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{service_upper}")
            if response.status_code == 200:
                service_data = response.json()
                if service_data and service_data.get('found') and 'mapping' in service_data:
                    mapping = service_data['mapping']
                    return {
                        'protocol': mapping.get('protocol'),
                        'port': mapping.get('port_number'),
                        'service_name': mapping.get('service_name') or service
                    }
        except Exception:
            pass
        
        # Try to lookup service by port number if we have a valid port
        try:
            # Check if we have a port number from previous parsing attempts
            if 'port' in locals() and port is not None:
                response = requests.get(f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{port}")
                if response.status_code == 200:
                    service_data = response.json()
                    if service_data and service_data.get('services'):
                        # Use the first service found for this port
                        mapping = service_data['services'][0]
                        return {
                            'protocol': mapping.get('protocol'),
                            'port': port,
                            'service_name': mapping.get('service_name') or f"{mapping.get('protocol')}-{port}"
                        }
        except Exception:
            pass
        
        # Handle service-* patterns
        if service_upper.startswith('SERVICE-'):
            service_name = service_upper[8:]  # Remove "SERVICE-" prefix
            try:
                response = requests.get(f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{service_name}")
                if response.status_code == 200:
                    service_data = response.json()
                    if service_data and service_data.get('found') and 'mapping' in service_data:
                        mapping = service_data['mapping']
                        return {
                            'protocol': mapping.get('protocol'),
                            'port': mapping.get('port_number'),
                            'service_name': mapping.get('service_name') or service_name
                        }
            except Exception:
                pass
        
        # If no parsing succeeded, return as protocol only (for services like "HTTPS" without explicit port)
        return {
            'protocol': service,
            'port': None,
            'service_name': original_field
        }

    def calculate_risk_score(self, rule_data: Dict[str, Any]) -> int:
        """Calculate a risk score for the normalized rule"""
        risk_score = 0
        
        # High risk factors
        action = rule_data.get('action') or ''
        if action.lower() == 'permit':
            risk_score += 2
        
        if rule_data.get('destination_port') in ['22', '3389', '23', '21']:  # SSH, RDP, Telnet, FTP
            risk_score += 3
        
        if rule_data.get('source_ip') in ['any', 'Any', 'ANY', '0.0.0.0/0']:
            risk_score += 4
        
        if rule_data.get('destination_ip') in ['any', 'Any', 'ANY', '0.0.0.0/0']:
            risk_score += 3
        
        # Environment-based risk
        if rule_data.get('source_environment') == 'production':
            risk_score += 1
        if rule_data.get('destination_environment') == 'production':
            risk_score += 2
        
        return min(risk_score, 10)  # Cap at 10
    
    def _extract_first_ip_for_enrichment(self, ip_field: str) -> str:
        """
        Extract a usable IP address for enrichment from a field that may contain
        object-group names, ranges, CIDRs, or multiple tokens.
        """
        if not ip_field or ip_field.strip() == '':
            return ''

        ip_field = ip_field.strip()

        def _ip_from_token(token: str) -> Optional[str]:
            t = token.strip()
            if not t:
                return None
            # CIDR: take base IP
            if '/' in t:
                base = t.split('/', 1)[0].strip()
                try:
                    ipaddress.ip_address(base)
                    return base
                except Exception:
                    pass
            # Range: take first
            if '-' in t:
                first = t.split('-', 1)[0].strip()
                try:
                    ipaddress.ip_address(first)
                    return first
                except Exception:
                    pass
            # Extract IPv4 literal within text
            m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t)
            if m:
                candidate = m.group(0)
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except Exception:
                    pass
            return None

        # Split possible multi-token values by common separators
        tokens = [s.strip() for s in re.split(r"[;,]", ip_field) if s.strip()] or [ip_field]

        # If any token looks like an object group, expand and search its members
        for tok in tokens:
            if self.is_object_group(tok) or tok.lower().startswith('object-group'):
                members = self.get_object_group_members(tok)
                for m in members:
                    ip_candidate = _ip_from_token(m)
                    if ip_candidate:
                        return ip_candidate
            # Support ASA 'object ' token with H_/R_ heuristics
            tll = tok.lower()
            if tll.startswith('object '):
                name = tok.split(' ', 1)[1].strip()
                if re.match(r'(?i)^H_\d{1,3}(?:\.\d{1,3}){3}$', name):
                    ip_candidate = name.split('_', 1)[1]
                    try:
                        ipaddress.ip_address(ip_candidate)
                        return ip_candidate
                    except Exception:
                        pass
                m_range_full = re.match(r'(?i)^R_(\d{1,3}(?:\.\d{1,3}){3})[-_](\d{1,3}(?:\.\d{1,3}){3})$', name)
                if m_range_full:
                    start_ip = m_range_full.group(1)
                    try:
                        ipaddress.ip_address(start_ip)
                        return start_ip
                    except Exception:
                        pass
                m_last_octet = re.match(r'(?i)^R_((?:\d{1,3}\.){3})(\d{1,3})[-_](\d{1,3})$', name)
                if m_last_octet:
                    prefix = m_last_octet.group(1)
                    d_start = m_last_octet.group(2)
                    start_ip = f"{prefix}{d_start}"
                    try:
                        ipaddress.ip_address(start_ip)
                        return start_ip
                    except Exception:
                        pass

        # Otherwise, try tokens directly
        for tok in tokens:
            ip_candidate = _ip_from_token(tok)
            if ip_candidate:
                return ip_candidate

        # Fallback: return original
        return ip_field

    def normalize_single_rule(self, raw_rule: RawFirewallRule) -> List[NormalizedRule]:
        """Normalize a single raw firewall rule.
        When expand_services=False, create exactly one normalized rule per raw rule (1:1 mapping).
        When expand_services=True, create one normalized rule per service/port token.
        """
        try:
            # Use original values without expansion to maintain 1:1 mapping
            source_ip = raw_rule.source or ''
            dest_ip = raw_rule.destination or ''
            
            # Apply AND condition logic for source zone + source
            source_zone = getattr(raw_rule, 'source_zone', None)
            if source_zone and source_zone.upper() == 'ANY' and source_ip:
                # When source zone is "Any" and source IP is specified, use only the source IP
                # This implements the AND condition logic
                pass  # source_ip remains as is
            elif source_zone and source_zone.upper() != 'ANY' and source_ip:
                # When source zone is specific and source IP is specified, apply AND logic
                # Use the source IP as is, zone information is preserved separately
                pass  # source_ip remains as is
            
            # Apply AND condition logic for destination zone + destination  
            dest_zone = getattr(raw_rule, 'dest_zone', None)
            if dest_zone and dest_zone.upper() == 'ANY' and dest_ip:
                # When destination zone is "Any" and destination IP is specified, use only the destination IP
                pass  # dest_ip remains as is
            elif dest_zone and dest_zone.upper() != 'ANY' and dest_ip:
                # When destination zone is specific and destination IP is specified, apply AND logic
                pass  # dest_ip remains as is
            
            expanded_sources = self.expand_object_group_field(source_ip)
            expanded_dests = self.expand_object_group_field(dest_ip)
            source_ip_str = ';'.join([s for s in expanded_sources if s]) if expanded_sources else source_ip
            dest_ip_str = ';'.join([d for d in expanded_dests if d]) if expanded_dests else dest_ip
            try:
                needs_src_fallback = bool(source_ip_str) and (
                    source_ip_str.strip().lower().startswith('object-group ') or
                    source_ip_str.strip().lower().startswith('object ') or
                    self.is_object_group(source_ip_str)
                )
                needs_dst_fallback = bool(dest_ip_str) and (
                    dest_ip_str.strip().lower().startswith('object-group ') or
                    dest_ip_str.strip().lower().startswith('object ') or
                    self.is_object_group(dest_ip_str)
                )
            except Exception:
                needs_src_fallback = False
                needs_dst_fallback = False
            if needs_src_fallback or needs_dst_fallback:
                s_det, d_det = self.expand_from_raw_details(raw_rule)
                if needs_src_fallback and s_det:
                    source_ip_str = s_det
                if needs_dst_fallback and d_det:
                    dest_ip_str = d_det
                # Persist virtual object-groups so they appear in Object Groups page
                try:
                    src_field = raw_rule.source
                    dst_field = raw_rule.destination
                    if src_field and s_det:
                        for g in self.extract_group_names_from_field(src_field):
                            self.upsert_virtual_object_group(g, [t.strip() for t in s_det.split(';') if t.strip()], source_file=raw_rule.source_file)
                    if dst_field and d_det:
                        for g in self.extract_group_names_from_field(dst_field):
                            self.upsert_virtual_object_group(g, [t.strip() for t in d_det.split(';') if t.strip()], source_file=raw_rule.source_file)
                except Exception:
                    pass
            protocol = raw_rule.protocol or ''
            dest_port = raw_rule.dest_port or ''
            if dest_port:
                dest_port = self._expand_service_object_groups(dest_port)

            is_disabled = bool(getattr(raw_rule, 'is_disabled', False))
            action_val = raw_rule.action or ''
            if is_disabled:
                action_tokens = [t.strip() for t in re.split(r"[;\,\|\s]+", action_val.lower()) if t.strip()]
                if 'disabled' not in action_tokens:
                    action_val = (f"{action_val} disabled").strip() if action_val.strip() else 'disabled'
            
            # For enrichment, try to get the first IP if it's a range or object group
            # but keep the original value in the normalized rule
            source_ip_for_enrichment = self._extract_first_ip_for_enrichment(source_ip)
            dest_ip_for_enrichment = self._extract_first_ip_for_enrichment(dest_ip)
            
            # Enrich source IP data (using first IP for lookup, but keeping original value)
            source_enrichment = self.enrich_ip_data(source_ip_for_enrichment)
            
            # Enrich destination IP data (using first IP for lookup, but keeping original value)
            destination_enrichment = self.enrich_ip_data(dest_ip_for_enrichment)
            
            
            service_field = dest_port if (dest_port and '/' in str(dest_port)) else (f"{protocol}/{dest_port}" if protocol and dest_port else protocol or dest_port)
            if not service_field:
                try:
                    allow_protocol = True
                    allow_dest_port = True
                    try:
                        rt_json = None
                        if raw_rule.raw_text:
                            try:
                                rt_json = json.loads(raw_rule.raw_text)
                            except Exception:
                                rt_json = None
                        mapped_fields = set()
                        if isinstance(rt_json, dict) and '__mapped_fields__' in rt_json:
                            mf = rt_json.get('__mapped_fields__') or []
                            mapped_fields = {str(x).strip().lower() for x in (mf if isinstance(mf, list) else [])}
                        allow_protocol = ('protocol' in mapped_fields) or ('service' in mapped_fields) or ('proto' in mapped_fields)
                        allow_dest_port = ('dest_port' in mapped_fields) or ('destination port' in mapped_fields) or ('service' in mapped_fields) or ('service_port' in mapped_fields) or ('port_protocol' in mapped_fields)
                    except Exception:
                        pass
                    
                    if allow_protocol or allow_dest_port:
                        candidates = []
                        def add_candidate(val):
                            if val and str(val).strip():
                                candidates.append(str(val).strip())
                        text_sources = [str(raw_rule.rule_text or ''), str(raw_rule.raw_text or '')]
                        keys = ['service','svc','services','application','service_port','port','ports','dst port','dest port','destination port','protocol']
                        for ts in text_sources:
                            if not ts:
                                continue
                            parts = [p for p in ts.split(';') if p]
                            for part in parts:
                                if ':' in part:
                                    k, v = part.split(':', 1)
                                    kl = k.strip().lower().replace('_', ' ')
                                    if kl in keys:
                                        add_candidate(v)
                        try:
                            if isinstance(rt_json, dict) and rt_json:
                                for k, v in rt_json.items():
                                    kl = str(k).strip().lower().replace('_', ' ')
                                    if kl in keys and isinstance(v, str) and v.strip():
                                        add_candidate(v)
                        except Exception:
                            pass
                        # Always include raw fields
                        add_candidate(raw_rule.dest_port)
                        add_candidate(raw_rule.protocol)
                        from protocol_port_parser import resolve_protocol_port_from_mixed_field
                        merged_ports = []
                        chosen_protocol = None
                        seen = set()
                        for val in candidates:
                            resolved = resolve_protocol_port_from_mixed_field(val)
                            rp = str(resolved.get('dest_port') or '').strip()
                            if rp and allow_dest_port:
                                for p in [t.strip() for t in rp.split(';') if t.strip()]:
                                    if p not in seen:
                                        seen.add(p)
                                        merged_ports.append(p)
                            proto = resolved.get('protocol')
                            if proto and not chosen_protocol and allow_protocol:
                                chosen_protocol = proto
                        if merged_ports and chosen_protocol:
                            service_field = f"{chosen_protocol}/" + ';'.join(merged_ports)
                        elif merged_ports:
                            service_field = ';'.join(merged_ports)
                        elif chosen_protocol:
                            service_field = chosen_protocol
                except Exception:
                    pass
            parsed_services = self.parse_protocol_service_field(service_field)
            normalized_rules = []

            if not self.expand_services:
                # Aggregate ports and service names into a single normalized rule
                ports = [str(ps['port']) for ps in parsed_services if ps.get('port')]
                seen_ports = set()
                dedup_ports = []
                for p in ports:
                    if p and p not in seen_ports:
                        seen_ports.add(p)
                        dedup_ports.append(p)
                services = [ps.get('service_name') for ps in parsed_services if ps.get('service_name')]
                proto_candidates = [ps.get('protocol') for ps in parsed_services if ps.get('protocol')]
                valid = {'TCP','UDP','ICMP','IP'}
                unique_proto = list({str(p).upper() for p in proto_candidates if p and str(p).upper() in valid})
                if unique_proto:
                    if len(unique_proto) == 1:
                        final_protocol = unique_proto[0]
                    elif set(p.lower() for p in unique_proto) == {'tcp','udp'}:
                        final_protocol = 'tcp/udp'
                    else:
                        final_protocol = ';'.join(unique_proto)
                else:
                    final_protocol = protocol
                final_dest_port = (';'.join(dedup_ports) if dedup_ports else dest_port)

                # Apply precedence: if services are ANY and application is specific, restrict to application mapping
                def _is_any(val: Optional[str]) -> bool:
                    v = (str(val or '')).strip().upper()
                    return v in {'', 'ANY', '-', 'NONE'}

                application_val = getattr(raw_rule, 'application', None)
                service_specific = bool(final_dest_port and str(final_dest_port).strip())
                # Also treat parsed services with any concrete port as specific
                if not service_specific:
                    service_specific = any(ps.get('port') for ps in parsed_services)
                if not service_specific and not _is_any(application_val):
                    try:
                        from protocol_port_parser import parse_service_field
                        app_parsed = parse_service_field(str(application_val))
                        app_proto = app_parsed.get('protocol')
                        app_port = app_parsed.get('port')
                        app_name = app_parsed.get('service_name') or str(application_val)
                        if app_proto and app_port:
                            final_protocol = app_proto
                            final_dest_port = app_port
                            services = [app_name]
                    except Exception:
                        pass

                rule_data = {
                    'raw_rule_id': raw_rule.id,
                    'source_file': raw_rule.source_file,
                    'rule_name': raw_rule.rule_name,  # Copy rule name from raw rule
                    'rule_type': raw_rule.rule_type or 'access_list',
                    'action': action_val,
                    'is_disabled': is_disabled,
                    'protocol': final_protocol,
                    'source_zone': getattr(raw_rule, 'source_zone', None),
                    'source_ip': source_ip_str,
                    'source_ip_with_zone': self.format_source_with_zone(source_ip_str, getattr(raw_rule, 'source_zone', None)),
                    'source_port': raw_rule.source_port,
                    'source_hostname': source_enrichment['hostname'],
                    'source_owner': source_enrichment['owner'],
                    'source_department': source_enrichment['business_unit'],
                    'source_environment': source_enrichment['environment'],
                    'source_vlan_id': source_enrichment['vlan_id'],
                    'source_vlan_name': source_enrichment['vlan_name'],
                    'source_subnet': source_enrichment['network_segment'],
                    'source_location': source_enrichment['location'],
                    'application': getattr(raw_rule, 'application', None),
                    'dest_ip': dest_ip_str,
                    'dest_ip_with_zone': self.format_destination_with_zone(dest_ip_str, getattr(raw_rule, 'dest_zone', None)),
                    'dest_port': final_dest_port,
                    'dest_hostname': destination_enrichment['hostname'],
                    'dest_owner': destination_enrichment['owner'],
                    'dest_department': destination_enrichment['business_unit'],
                    'dest_environment': destination_enrichment['environment'],
                    'dest_vlan_id': destination_enrichment['vlan_id'],
                    'dest_vlan_name': destination_enrichment['vlan_name'],
                    'dest_subnet': destination_enrichment['network_segment'],
                    'dest_location': destination_enrichment['location'],
                    'dest_zone': getattr(raw_rule, 'dest_zone', None),
                    'service_name': ';'.join([s for s in services if s]) or (protocol or dest_port),
                    'service_port': final_dest_port,
                    'service_protocol': final_protocol
                }
                try:
                    hc = raw_rule.hit_count
                except Exception:
                    hc = None
                
                # Add hit_count to rule_data
                if hc is not None:
                    try:
                        rule_data['hit_count'] = int(hc)
                    except (ValueError, TypeError):
                        pass

                # Calculate risk score using enrichment IPs for analysis
                rule_data_for_risk = {
                    'action': raw_rule.action,
                    'destination_port': final_dest_port,
                    'source_ip': source_ip_for_enrichment,
                    'destination_ip': dest_ip_for_enrichment,
                    'source_environment': source_enrichment['environment'],
                    'destination_environment': destination_enrichment['environment']
                }
                # Calculate risk score and map to risk level
                risk_score = self.calculate_risk_score(rule_data_for_risk)
                if risk_score <= 2:
                    risk_level = 'low'
                elif risk_score <= 5:
                    risk_level = 'medium'
                elif risk_score <= 8:
                    risk_level = 'high'
                else:
                    risk_level = 'critical'
                
                rule_data['risk_level'] = risk_level
                
                # Set compliance flags (basic implementation)
                rule_data['compliance_status'] = 'compliant' if risk_score <= 5 else 'non_compliant'
                
                # Populate custom fields data
                rule_data_cf = dict(rule_data)
                if hc is not None:
                    rule_data_cf['hit_count'] = hc
                custom_fields_data = self.populate_custom_fields(raw_rule, rule_data_cf)
                if custom_fields_data:
                    rule_data['custom_fields_data'] = json.dumps(custom_fields_data)
                
                # Create normalized rule object
                normalized_rule = NormalizedRule(**rule_data)
                normalized_rules.append(normalized_rule)
                
                self.stats['normalized_rules_created'] += 1
            else:
                # Expand into one normalized rule per parsed service (existing behavior)
                for parsed_service in parsed_services:
                    final_protocol = parsed_service['protocol'] or protocol
                    final_dest_port = parsed_service['port'] or dest_port
                    # If this parsed service yielded no specific port and application is specific, use application mapping
                    def _is_any(val: Optional[str]) -> bool:
                        v = (str(val or '')).strip().upper()
                        return v in {'', 'ANY', '-', 'NONE'}
                    application_val = getattr(raw_rule, 'application', None)
                    if (not final_dest_port or not str(final_dest_port).strip()) and not _is_any(application_val):
                        try:
                            from protocol_port_parser import parse_service_field
                            app_parsed = parse_service_field(str(application_val))
                            app_proto = app_parsed.get('protocol')
                            app_port = app_parsed.get('port')
                            app_name = app_parsed.get('service_name') or str(application_val)
                            if app_proto and app_port:
                                final_protocol = app_proto
                                final_dest_port = app_port
                                parsed_service = {'protocol': app_proto, 'port': app_port, 'service_name': app_name}
                        except Exception:
                            pass
                    rule_data = {
                        'raw_rule_id': raw_rule.id,
                        'source_file': raw_rule.source_file,
                        'rule_name': raw_rule.rule_name,
                        'rule_type': raw_rule.rule_type or 'access_list',
                        'action': action_val,
                        'is_disabled': is_disabled,
                        'protocol': final_protocol,
                        'source_zone': getattr(raw_rule, 'source_zone', None),
                        'source_ip': source_ip_str,
                        'source_ip_with_zone': self.format_source_with_zone(source_ip_str, getattr(raw_rule, 'source_zone', None)),
                        'source_port': raw_rule.source_port,
                        'source_hostname': source_enrichment['hostname'],
                        'source_owner': source_enrichment['owner'],
                        'source_department': source_enrichment['business_unit'],
                        'source_environment': source_enrichment['environment'],
                        'source_vlan_id': source_enrichment['vlan_id'],
                        'source_vlan_name': source_enrichment['vlan_name'],
                        'source_subnet': source_enrichment['network_segment'],
                        'application': getattr(raw_rule, 'application', None),
                        'dest_ip': dest_ip_str,
                        'dest_ip_with_zone': self.format_destination_with_zone(dest_ip_str, getattr(raw_rule, 'dest_zone', None)),
                        'dest_port': final_dest_port,
                        'dest_hostname': destination_enrichment['hostname'],
                        'dest_owner': destination_enrichment['owner'],
                        'dest_department': destination_enrichment['business_unit'],
                        'dest_environment': destination_enrichment['environment'],
                        'dest_vlan_id': destination_enrichment['vlan_id'],
                        'dest_vlan_name': destination_enrichment['vlan_name'],
                        'dest_subnet': destination_enrichment['network_segment'],
                        'dest_zone': getattr(raw_rule, 'dest_zone', None),
                        'service_name': parsed_service['service_name'],
                        'service_port': final_dest_port,
                        'service_protocol': final_protocol
                    }
                    try:
                        hc = raw_rule.hit_count
                    except Exception:
                        hc = None
                    
                    if hc is not None:
                        try:
                            rule_data['hit_count'] = int(hc)
                        except (ValueError, TypeError):
                            pass

                    rule_data_for_risk = {
                        'action': raw_rule.action,
                        'destination_port': final_dest_port,
                        'source_ip': source_ip_for_enrichment,
                        'destination_ip': dest_ip_for_enrichment,
                        'source_environment': source_enrichment['environment'],
                        'destination_environment': destination_enrichment['environment']
                    }
                    risk_score = self.calculate_risk_score(rule_data_for_risk)
                    if risk_score <= 2:
                        risk_level = 'low'
                    elif risk_score <= 5:
                        risk_level = 'medium'
                    elif risk_score <= 8:
                        risk_level = 'high'
                    else:
                        risk_level = 'critical'
                    rule_data['risk_level'] = risk_level
                    rule_data['compliance_status'] = 'compliant' if risk_score <= 5 else 'non_compliant'
                    rule_data_cf = dict(rule_data)
                    if hc is not None:
                        rule_data_cf['hit_count'] = hc
                    custom_fields_data = self.populate_custom_fields(raw_rule, rule_data_cf)
                    if custom_fields_data:
                        rule_data['custom_fields_data'] = json.dumps(custom_fields_data)
                    normalized_rule = NormalizedRule(**rule_data)
                    normalized_rules.append(normalized_rule)
                    self.stats['normalized_rules_created'] += 1

            return normalized_rules
            
        except Exception as e:
            logger.error(f"Error normalizing rule {raw_rule.id}: {str(e)}")
            self.stats['errors'] += 1
            return []

    def populate_custom_fields(self, raw_rule: RawFirewallRule, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Populate custom field values for a normalized rule
        
        Args:
            raw_rule: The raw firewall rule being normalized
            rule_data: The normalized rule data dictionary
            
        Returns:
            Dictionary of custom field values
        """
        custom_fields_data = {}
        
        try:
            # Get all custom fields
            custom_fields = self.custom_fields_service.get_all_fields()
            
            for custom_field in custom_fields:
                field_name = custom_field['field_name']
                field_type = custom_field['field_type']
                
                # Calculate custom field value based on the field logic
                # This is a simplified implementation - you may need to enhance based on your custom field requirements
                field_value = self.calculate_custom_field_value(custom_field, raw_rule, rule_data)
                
                if field_value is not None:
                    custom_fields_data[field_name] = field_value
                    
        except Exception as e:
            logger.warning(f"Error populating custom fields: {str(e)}")
            
        return custom_fields_data
    
    def calculate_custom_field_value(self, custom_field: Dict[str, Any], raw_rule: RawFirewallRule, rule_data: Dict[str, Any]) -> Any:
        """
        Calculate the value for a custom field based on the rule data
        
        Args:
            custom_field: Custom field definition
            raw_rule: Raw firewall rule
            rule_data: Normalized rule data
            
        Returns:
            Calculated field value or None
        """
        field_name = custom_field['field_name']
        field_type = custom_field['field_type']

        # This is a basic implementation - enhance based on your custom field logic
        # For now, we'll try to map some common custom fields to existing rule data
        
        # Example mappings - customize based on your needs
        field_mappings = {
            'business_criticality': lambda: self.determine_business_criticality(rule_data),
            'data_classification': lambda: self.determine_data_classification(rule_data),
            'network_zone': lambda: self.determine_network_zone(rule_data),
            'application_name': lambda: self.determine_application_name(rule_data),
            'rule_purpose': lambda: self.determine_rule_purpose(rule_data),
        }
        
        if field_name in field_mappings:
            try:
                return field_mappings[field_name]()
            except Exception as e:
                logger.warning(f"Error calculating custom field {field_name}: {str(e)}")
                return None

        if field_name.strip().lower() == 'rule_name':
            try:
                rn = rule_data.get('rule_name') or (raw_rule.rule_name if raw_rule and raw_rule.rule_name else None)
                return rn if rn and str(rn).strip() else None
            except Exception:
                return None

        # Extract VPN setting from uploaded rows (e.g., "VPN: Any")
        if field_name.strip().lower() == 'vpn':
            try:
                v = rule_data.get('vpn')
                if isinstance(v, str) and v.strip():
                    return v.strip()
                # Try raw_text JSON
                rt = getattr(raw_rule, 'raw_text', None)
                parsed = None
                if rt:
                    try:
                        parsed = json.loads(rt)
                    except Exception:
                        parsed = None
                if isinstance(parsed, dict):
                    for k in ('vpn','VPN','Vpn'):
                        val = parsed.get(k)
                        if isinstance(val, str) and val.strip():
                            return val.strip()
                # Parse rule_text key-value pairs
                s = getattr(raw_rule, 'rule_text', None) or getattr(raw_rule, 'raw_text', None)
                s = str(s or '')
                if s:
                    for part in [p.strip() for p in s.split(';') if p.strip()]:
                        if ':' in part:
                            key, val = part.split(':', 1)
                            if key.strip().lower() == 'vpn':
                                v2 = val.strip()
                                if v2:
                                    return v2
                return None
            except Exception:
                return None

        # Extract hit_count from uploaded CSV if present
        if field_name.strip().lower() == 'hit_count':
            try:
                # Helper to coerce numeric values safely
                def _to_int(val):
                    try:
                        if isinstance(val, (int, float)):
                            return int(val)
                        s = str(val).strip()
                        if not s:
                            return None
                        s = s.replace(',', '')
                        import re as _re
                        m = _re.search(r"[-+]?\d+", s)
                        if m:
                            return int(m.group(0))
                        return None
                    except Exception:
                        return None

                # 1) Directly from mapped normalized rule_data (if parser propagated)
                for k in ('hit_count', 'hits', 'hitcount'):
                    v = rule_data.get(k)
                    iv = _to_int(v)
                    if iv is not None:
                        return iv

                # 2) From raw_text if JSON payload was stored (some ingestion paths)
                try:
                    rt = getattr(raw_rule, 'raw_text', None)
                    if rt:
                        parsed = None
                        try:
                            parsed = json.loads(rt)
                        except Exception:
                            parsed = None
                        if isinstance(parsed, dict):
                            # Prefer exact expected keys
                            for k in ('hit_count', 'hits', 'hitcount'):
                                iv = _to_int(parsed.get(k))
                                if iv is not None:
                                    return iv
                            # Fallback: scan keys containing both 'hit' and 'count'
                            for k, v in parsed.items():
                                try:
                                    kl = str(k).strip().lower().replace('_', ' ')
                                    if ('hit' in kl) and ('count' in kl):
                                        iv = _to_int(v)
                                        if iv is not None:
                                            return iv
                                except Exception:
                                    continue
                except Exception:
                    pass

                # 3) From rule_text of form "key: value; ..." (CSV-generated)
                try:
                    rule_text = getattr(raw_rule, 'rule_text', None) or getattr(raw_rule, 'raw_text', None)
                    s = str(rule_text or '')
                    if s:
                        pairs = [p.strip() for p in s.split(';') if p.strip()]
                        for p in pairs:
                            if ':' in p:
                                key, val = p.split(':', 1)
                                kl = key.strip().lower().replace('_', ' ')
                                if (kl in ('hit count', 'hits', 'hitcount')) or (('hit' in kl) and ('count' in kl)):
                                    iv = _to_int(val)
                                    if iv is not None:
                                        return iv
                except Exception:
                    pass

                # Default when not found: do not set hit_count
                return None
            except Exception:
                return 0

        # Calculate service_count: number of ports/services represented in this normalized rule
        if field_name.strip().lower() == 'service_count':
            try:
                sp = str(rule_data.get('service_port') or '')
                if not sp:
                    return 0
                # Split by ';' to handle multiple tokens
                tokens = [t.strip() for t in sp.split(';') if t.strip()]
                count = 0
                for t in tokens:
                    tl = t.lower()
                    # Treat ANY/ALL/* as full port space to ensure flagging
                    if tl in ('any', 'all', '*'):
                        count += 65535
                        continue
                    # Handle numeric ranges like "80-90"
                    if '-' in t:
                        parts = t.split('-', 1)
                        try:
                            start = int(parts[0])
                            end = int(parts[1])
                            if end >= start:
                                count += (end - start + 1)
                            else:
                                count += 1
                        except Exception:
                            count += 1
                    else:
                        # Single port token; if numeric, count as 1
                        count += 1
                return count
            except Exception:
                return 0

        # Default behavior for unmapped fields
        if field_type == 'text':
            return f"Auto-generated for {field_name}"
        elif field_type == 'number':
            return 0
        elif field_type == 'boolean':
            return False
        elif field_type == 'select':
            # Return first option if available
            options = custom_field.get('options', [])
            return options[0] if options else None
            
        return None
    
    def determine_business_criticality(self, rule_data: Dict[str, Any]) -> str:
        """Determine business criticality based on rule characteristics"""
        # High criticality for production environments or sensitive ports
        if rule_data.get('dest_environment') == 'production':
            return 'High'
        elif rule_data.get('dest_port') in ['22', '3389', '443']:
            return 'Medium'
        else:
            return 'Low'
    
    def determine_data_classification(self, rule_data: Dict[str, Any]) -> str:
        """Determine data classification based on rule characteristics"""
        # Classify based on destination environment and ports
        if rule_data.get('dest_environment') == 'production':
            return 'Confidential'
        elif rule_data.get('dest_environment') == 'staging':
            return 'Internal'
        else:
            return 'Public'
    
    def format_source_with_zone(self, source_ip: str, source_zone: str) -> str:
        """Format source IP with zone information to show AND logic"""
        if not source_zone or source_zone.upper() == 'ANY':
            return source_ip
        else:
            return f"{source_zone} AND {source_ip}"
    
    def format_destination_with_zone(self, dest_ip: str, dest_zone: str) -> str:
        """Format destination IP with zone information to show AND logic"""
        if not dest_zone or dest_zone.upper() == 'ANY':
            return dest_ip
        else:
            return f"{dest_zone} AND {dest_ip}"
    
    def determine_network_zone(self, rule_data: Dict[str, Any]) -> str:
        """Determine network zone based on IP addresses"""
        dest_ip = rule_data.get('dest_ip', '')
        if dest_ip.startswith('10.'):
            return 'Internal'
        elif dest_ip.startswith('192.168.'):
            return 'DMZ'
        else:
            return 'External'
    
    def determine_application_name(self, rule_data: Dict[str, Any]) -> str:
        """Determine application name based on ports and services using service mapping API"""
        dest_port = rule_data.get('dest_port', '')
        
        if not dest_port or not dest_port.isdigit():
            return 'Unknown Application'
        
        try:
            port_num = int(dest_port)
            # Try to get service name from API
            service_name = get_service_name_for_port(port_num)
            if service_name:
                return f"{service_name} Server"
            
            # Fallback for common ports if API is unavailable
            fallback_mappings = {
                80: 'Web',
                443: 'HTTPS', 
                22: 'SSH',
                3389: 'RDP',
                25: 'Mail',
                53: 'DNS'
            }
            if port_num in fallback_mappings:
                return f"{fallback_mappings[port_num]} Server"
                
        except (ValueError, TypeError):
            pass
            
        return 'Unknown Application'
    
    def determine_rule_purpose(self, rule_data: Dict[str, Any]) -> str:
        """Determine rule purpose based on action and characteristics"""
        action = rule_data.get('action') or ''
        if action.lower() == 'permit':
            return 'Allow Access'
        elif action.lower() == 'deny':
            return 'Block Access'
        else:
            return 'Unknown Purpose'
    
    def normalize_all_rules(self, source_file: str = None, clear_existing: bool = True) -> Dict[str, Any]:
        """
        Normalize all raw firewall rules
        
        Args:
            source_file: Optional filter to normalize rules from specific file
            clear_existing: Whether to clear existing normalized rules first
            
        Returns:
            Dictionary with normalization results
        """
        try:
            logger.info("Starting rule normalization process...")
            
            # Clear existing normalized rules if requested
            if clear_existing:
                if source_file:
                    db.session.query(NormalizedRule).filter_by(source_file=source_file).delete()
                else:
                    db.session.query(NormalizedRule).delete()
                db.session.commit()
                logger.info("Cleared existing normalized rules")
            elif source_file:
                # When not clearing all existing rules but processing a specific file,
                # we still need to clear existing normalized rules for that specific file
                # to avoid duplicates
                db.session.query(NormalizedRule).filter_by(source_file=source_file).delete()
                db.session.commit()
                logger.info(f"Cleared existing normalized rules for source file: {source_file}")
            
            # Reset stats
            self.stats = {key: 0 for key in self.stats}
            
            # Query raw firewall rules
            query = db.session.query(RawFirewallRule)
            if source_file:
                query = query.filter(RawFirewallRule.source_file == source_file)
            
            raw_rules = query.all()
            logger.info(f"Processing {len(raw_rules)} raw firewall rules")

            if self.group_by_remark:
                groups = {}
                for rr in raw_rules:
                    if rr.rule_name and rr.rule_name.strip():
                        key = (rr.source_file or '', rr.rule_name.strip())
                        groups.setdefault(key, []).append(rr)
                grouped_ids = set()
                for gkey, grules in groups.items():
                    if not grules:
                        continue
                    base = grules[0]
                    actions = [r.action for r in grules if r.action]
                    protocols = [r.protocol for r in grules if r.protocol]
                    sources = [r.source for r in grules if r.source]
                    destinations = [r.destination for r in grules if r.destination]
                    ports = [r.dest_port for r in grules if r.dest_port]
                    uniq_action = list({a for a in actions if a})
                    uniq_proto = list({p for p in protocols if p})
                    agg_source = ';'.join(sorted({s for s in sources if s}))
                    agg_dest = ';'.join(sorted({d for d in destinations if d}))
                    src_tokens = [t.strip() for t in agg_source.split(';') if t.strip()]
                    dst_tokens = [t.strip() for t in agg_dest.split(';') if t.strip()]
                    expanded_src = []
                    for tok in src_tokens:
                        if self.is_object_group(tok) or tok.lower().startswith('object-group'):
                            m = self.get_object_group_members(tok)
                            expanded_src.extend(m if m else [tok])
                        else:
                            expanded_src.append(tok)
                    expanded_dst = []
                    for tok in dst_tokens:
                        if self.is_object_group(tok) or tok.lower().startswith('object-group'):
                            m = self.get_object_group_members(tok)
                            expanded_dst.extend(m if m else [tok])
                        else:
                            expanded_dst.append(tok)
                    agg_source = ';'.join(expanded_src)
                    agg_dest = ';'.join(expanded_dst)
                    agg_port = ';'.join(sorted({str(p) for p in ports if p}))
                    if agg_port:
                        agg_port = self._expand_service_object_groups(agg_port)
                    protocol = base.protocol or (uniq_proto[0] if len(uniq_proto) == 1 else '')
                    service_field = agg_port if (agg_port and '/' in str(agg_port)) else (f"{protocol}/{agg_port}" if protocol and agg_port else protocol or agg_port)
                    if not service_field:
                        try:
                            rt_json = None
                            if base.raw_text:
                                try:
                                    rt_json = json.loads(base.raw_text)
                                except Exception:
                                    rt_json = None
                            # Prefer mapped service field when present
                            candidate_service = None
                            if isinstance(rt_json, dict):
                                # Direct canonical 'service'
                                if 'service' in rt_json and rt_json.get('service'):
                                    candidate_service = str(rt_json.get('service'))
                                # Vendor CSV header variant
                                if not candidate_service:
                                    for k in rt_json.keys():
                                        kl = str(k).strip().lower().replace('_',' ')
                                        if kl in ('services & applications', 'services and applications', 'service', 'services'):
                                            val = rt_json.get(k)
                                            if val:
                                                candidate_service = str(val)
                                                break
                            # Fallback to rule_text if serialized as key:value;
                            if not candidate_service:
                                s = str(base.rule_text or '')
                                parts = [p.strip() for p in s.split(';') if p.strip()]
                                for part in parts:
                                    if ':' in part:
                                        k, v = part.split(':', 1)
                                        kl = str(k).strip().lower().replace('_',' ')
                                        if kl in ('services & applications', 'services and applications', 'service', 'services'):
                                            if v and str(v).strip():
                                                candidate_service = str(v).strip()
                                                break
                            if candidate_service:
                                service_field = candidate_service
                        except Exception:
                            pass
                    parsed_services = self.parse_protocol_service_field(service_field)
                    ports_list = [str(ps['port']) for ps in parsed_services if ps.get('port')]
                    services_list = [ps.get('service_name') for ps in parsed_services if ps.get('service_name')]
                    final_protocol = protocol or (list({ps.get('protocol') for ps in parsed_services if ps.get('protocol')})[0] if len({ps.get('protocol') for ps in parsed_services if ps.get('protocol')}) == 1 else protocol)
                    final_dest_port = (';'.join(ports_list) if ports_list else agg_port)
                    src_enrich_ip = self._extract_first_ip_for_enrichment(agg_source)
                    dst_enrich_ip = self._extract_first_ip_for_enrichment(agg_dest)
                    source_enrichment = self.enrich_ip_data(src_enrich_ip)
                    destination_enrichment = self.enrich_ip_data(dst_enrich_ip)
                    rule_data = {
                        'raw_rule_id': base.id,
                        'source_file': base.source_file,
                        'rule_name': base.rule_name,
                        'rule_type': base.rule_type or 'access_list',
                        'action': base.action or (uniq_action[0] if uniq_action else None),
                    'protocol': final_protocol,
                    'source_ip': agg_source,
                    'source_ip_with_zone': self.format_source_with_zone(agg_source, getattr(base, 'source_zone', None)),
                    'source_port': base.source_port,
                    'source_hostname': source_enrichment['hostname'],
                    'source_owner': source_enrichment['owner'],
                    'source_department': source_enrichment['business_unit'],
                    'source_environment': source_enrichment['environment'],
                    'source_vlan_id': source_enrichment['vlan_id'],
                    'source_vlan_name': source_enrichment['vlan_name'],
                    'source_subnet': source_enrichment['network_segment'],
                    'dest_ip': agg_dest,
                    'dest_ip_with_zone': self.format_destination_with_zone(agg_dest, getattr(base, 'dest_zone', None)),
                    'dest_port': final_dest_port,
                    'dest_hostname': destination_enrichment['hostname'],
                    'dest_owner': destination_enrichment['owner'],
                    'dest_department': destination_enrichment['business_unit'],
                    'dest_environment': destination_enrichment['environment'],
                    'dest_vlan_id': destination_enrichment['vlan_id'],
                        'dest_vlan_name': destination_enrichment['vlan_name'],
                        'dest_subnet': destination_enrichment['network_segment'],
                        'service_name': ';'.join([s for s in services_list if s]) or (protocol or final_dest_port),
                        'service_port': final_dest_port,
                        'service_protocol': final_protocol
                    }
                    rule_data_for_risk = {
                        'action': rule_data['action'],
                        'destination_port': final_dest_port,
                        'source_ip': src_enrich_ip,
                        'destination_ip': dst_enrich_ip,
                        'source_environment': source_enrichment['environment'],
                        'destination_environment': destination_enrichment['environment']
                    }
                    risk_score = self.calculate_risk_score(rule_data_for_risk)
                    if risk_score <= 2:
                        risk_level = 'low'
                    elif risk_score <= 5:
                        risk_level = 'medium'
                    elif risk_score <= 8:
                        risk_level = 'high'
                    else:
                        risk_level = 'critical'
                    rule_data['risk_level'] = risk_level
                    rule_data['compliance_status'] = 'compliant' if risk_score <= 5 else 'non_compliant'
                    custom_fields_data = self.populate_custom_fields(base, rule_data)
                    if custom_fields_data:
                        rule_data['custom_fields_data'] = json.dumps(custom_fields_data)
                    normalized_rule = NormalizedRule(**rule_data)
                    db.session.add(normalized_rule)
                    self.stats['normalized_rules_created'] += 1
                    for r in grules:
                        grouped_ids.add(r.id)
                    self.stats['rules_processed'] += len(grules)

                batch_size = 100
                remaining = [rr for rr in raw_rules if rr.id not in grouped_ids]
                for i in range(0, len(remaining), batch_size):
                    batch = remaining[i:i + batch_size]
                    for raw_rule in batch:
                        normalized_rules = self.normalize_single_rule(raw_rule)
                        for normalized_rule in normalized_rules:
                            db.session.add(normalized_rule)
                        self.stats['rules_processed'] += 1
                    db.session.commit()
                    logger.info(f"Processed batch {i//batch_size + 1}/{(len(remaining) + batch_size - 1)//batch_size}")
            else:
                batch_size = 100
                for i in range(0, len(raw_rules), batch_size):
                    batch = raw_rules[i:i + batch_size]
                    for raw_rule in batch:
                        normalized_rules = self.normalize_single_rule(raw_rule)
                        for normalized_rule in normalized_rules:
                            db.session.add(normalized_rule)
                        self.stats['rules_processed'] += 1
                    db.session.commit()
                    logger.info(f"Processed batch {i//batch_size + 1}/{(len(raw_rules) + batch_size - 1)//batch_size}")
            
            # Final commit
            db.session.commit()
            
            results = {
                'success': True,
                'message': 'Rule normalization completed successfully',
                'stats': self.stats.copy(),
                'expand_services': self.expand_services
            }
            
            logger.info(f"Normalization completed: {self.stats}")
            return results
            
        except Exception as e:
            logger.error(f"Error during rule normalization: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'message': f'Rule normalization failed: {str(e)}',
                'stats': self.stats.copy()
            }

def normalize_firewall_rules(source_file: str = None, clear_existing: bool = True, expand_services: bool = False, group_by_remark: bool = False) -> Dict[str, Any]:
    """
    Convenience function to normalize firewall rules
    
    Args:
        source_file: Optional filter to normalize rules from specific file
        clear_existing: Whether to clear existing normalized rules first
        
    Returns:
        Dictionary with normalization results
    """
    normalizer = RuleNormalizer(expand_services=expand_services, group_by_remark=group_by_remark)
    return normalizer.normalize_all_rules(source_file, clear_existing)

if __name__ == "__main__":
    # Run normalizer when script is executed directly
    from app import app
    
    with app.app_context():
        print("Starting rule normalization...")
        results = normalize_firewall_rules()
        
        print("\n=== Rule Normalization Results ===")
        print(f"Success: {results['success']}")
        print(f"Message: {results['message']}")
        
        if results['stats']:
            print("\nStatistics:")
            for key, value in results['stats'].items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print("\nNormalization completed!")
