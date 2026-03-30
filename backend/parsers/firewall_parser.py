"""
Firewall Parser - Handles .txt/.conf firewall configuration files using regex patterns
"""
import re
from typing import Dict, List, Any, Optional, Pattern
from .base_parser import BaseParser


class FirewallParser(BaseParser):
    """Parser for firewall configuration files using regex patterns"""
    
    # Cisco ASA regex patterns
    CISCO_ASA_PATTERNS = {
        'access_list': re.compile(
            r'access-list\s+(\S+)\s+'
            r'(?:line\s+(\d+)\s+)?'
            r'(?:extended\s+)?'
            r'(permit|deny)\s+'
            r'(.*)'
        ),
        'remark': re.compile(
            r'access-list\s+(\S+)\s+(?:line\s+(\d+)\s+)?remark\s+(.+)$'
        ),
        'object_group_network': re.compile(
            r'object-group\s+network\s+(\S+)'
        ),
        'network_object': re.compile(
            r'network-object\s+(host\s+)?(\S+)(?:\s+(\S+))?'
        ),
        'object_group_service': re.compile(
            r'object-group\s+service\s+(\S+)(?:\s+(tcp|udp))?'
        ),
        'service_object_range': re.compile(
            r'service-object\s+(tcp|udp|tcp-udp)\s+(?:destination\s+)?range\s+(\d+)\s+(\d+)'
        ),
        'service_object': re.compile(
            r'service-object\s+(tcp|udp|tcp-udp|icmp)\s+(?:destination\s+)?(?:eq\s+)?(\S+)'
        ),
        'port_object_eq': re.compile(
            r'port-object\s+(?:destination\s+)?(?:eq\s+)?(\S+)'
        ),
        'port_object_range': re.compile(
            r'port-object\s+(?:destination\s+)?range\s+(\d+)\s+(\d+)'
        ),
        'object_network': re.compile(
            r'object\s+network\s+(\S+)'
        ),
        'object_service': re.compile(
            r'object\s+service\s+(\S+)'
        ),
        'object_host': re.compile(
            r'host\s+(\S+)'
        ),
        'object_subnet': re.compile(
            r'subnet\s+(\S+)\s+(\S+)'
        ),
        'object_range': re.compile(
            r'range\s+(\S+)\s+(\S+)'
        ),
        'object_service_line': re.compile(
            r'service\s+(tcp|udp|tcp-udp|icmp)\s+(?:destination\s+)?(?:eq\s+)?(\S+)'
        ),
        'nat_rule': re.compile(
            r'nat\s+\((\S+),(\S+)\)\s+(\d+)\s+source\s+(static|dynamic)\s+'
            r'(\S+)\s+(\S+)(?:\s+destination\s+(static)\s+(\S+)\s+(\S+))?'
        )
    }
    
    # Palo Alto patterns (placeholder for future expansion)
    PALO_ALTO_PATTERNS = {
        'security_rule': re.compile(
            r'set\s+rulebase\s+security\s+rules\s+(\S+)\s+'
        )
    }
    
    # Fortinet patterns (placeholder for future expansion)
    FORTINET_PATTERNS = {
        'firewall_policy': re.compile(
            r'config\s+firewall\s+policy'
        )
    }
    
    def __init__(self, file_path: str, file_type: str, **kwargs):
        super().__init__(file_path, file_type, **kwargs)
        self.vendor = kwargs.get('vendor', 'auto').lower()
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.patterns = self._get_patterns_for_vendor()
        # Track discovered object-group names for smarter ACL parsing
        self.known_service_groups = set()
        self.known_network_groups = set()
        self.current_context = {}
    
    def _get_patterns_for_vendor(self) -> Dict[str, Pattern]:
        """Get regex patterns based on vendor"""
        vendor_patterns = {
            'cisco_asa': self.CISCO_ASA_PATTERNS,
            'palo_alto': self.PALO_ALTO_PATTERNS,
            'fortinet': self.FORTINET_PATTERNS
        }
        
        return vendor_patterns.get(self.vendor, self.CISCO_ASA_PATTERNS)
    
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse firewall configuration file using regex patterns
        
        Returns:
            List of dictionaries containing parsed firewall rules
        """
        if not self.validate_file():
            raise ValueError(f"Invalid file: {self.file_path}")
        
        self.log_parsing_start()
        
        try:
            with open(self.file_path, 'r', encoding=self.encoding) as file:
                content = file.read()

            # Auto-detect vendor when requested
            if self.vendor in ('auto', 'unknown'):
                detected = self.detect_vendor(content)
                self.vendor = detected or 'unknown'
                self.patterns = self._get_patterns_for_vendor()

            # Parse based on vendor
            if self.vendor == 'cisco_asa':
                records = self._parse_cisco_asa(content)
            elif self.vendor == 'palo_alto':
                records = self._parse_palo_alto(content)
            elif self.vendor == 'fortinet':
                records = self._parse_fortinet(content)
            else:
                records = self._parse_generic(content)
            
            # Clean and validate records
            cleaned_records = self._clean_records(records)
            
            self.log_parsing_complete(len(cleaned_records))
            return cleaned_records
            
        except Exception as e:
            self.handle_parsing_error(e, "Firewall configuration parsing")
    
    def _parse_cisco_asa(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse Cisco ASA configuration
        
        Args:
            content: File content
            
        Returns:
            List of parsed records
        """
        records = []
        acl_groups = {}
        lines = content.split('\n')
        current_object_group = None
        line_number = 0
        
        for line in lines:
            line_number += 1
            raw_line = line
            line = line.strip()
            
            if not line or line.startswith('!'):
                continue
            
            remark_match = self.patterns.get('remark') and self.patterns['remark'].match(line)
            if remark_match:
                acl = remark_match.group(1)
                remark_text = remark_match.group(3)
                rule_name = self._extract_rule_name_from_remark(remark_text)
                self.current_context['acl'] = acl
                self.current_context['rule_name'] = rule_name
                continue
            
            # Parse access-list rules
            access_list_match = self.patterns['access_list'].match(line)
            if access_list_match:
                record = self._parse_access_list_rule(access_list_match, line, line_number)
                if record:
                    acl_name = record.get('acl_name')
                    ln = record.get('line_number_in_acl')
                    if acl_name and ln is not None:
                        key = (acl_name, ln)
                        hit_m = re.search(r"\(hitcnt=(\d+)\)", line)
                        hit_count = int(hit_m.group(1)) if hit_m else None
                        if key not in acl_groups:
                            base = dict(record)
                            if hit_count is not None:
                                base['hit_count'] = hit_count
                            base['details'] = []
                            acl_groups[key] = base
                        else:
                            det = {
                                'source': record.get('source'),
                                'destination': record.get('destination'),
                                'dest_port': record.get('dest_port'),
                                'raw_text': record.get('raw_text'),
                                'file_line_number': record.get('file_line_number')
                            }
                            acl_groups[key]['details'].append(det)
                            if hit_count is not None and 'hit_count' not in acl_groups[key]:
                                acl_groups[key]['hit_count'] = hit_count
                    else:
                        records.append(record)
                continue
            
            # Parse object-group network
            obj_group_net_match = self.patterns['object_group_network'].match(line)
            if obj_group_net_match:
                if current_object_group and current_object_group.get('members'):
                    records.append(current_object_group)
                current_object_group = {
                    'name': obj_group_net_match.group(1),
                    'rule_type': 'object_group',
                    'type': 'network',
                    'members': [],
                    'line_number': line_number,
                    'raw_text': line
                }
                # Remember network group name
                try:
                    self.known_network_groups.add(obj_group_net_match.group(1))
                except Exception:
                    pass
                continue
            
            # Parse network-object (inside object-group)
            if current_object_group and current_object_group['type'] == 'network':
                net_obj_match = self.patterns['network_object'].match(line)
                if net_obj_match:
                    member = self._parse_network_object(net_obj_match)
                    if member:
                        current_object_group['members'].append(member)
                    continue
                elif not raw_line.startswith(' '):
                    # End of object-group
                    if current_object_group['members']:
                        records.append(current_object_group)
                    current_object_group = None
            
            # Parse object-group service
            obj_group_svc_match = self.patterns['object_group_service'].match(line)
            if obj_group_svc_match:
                if current_object_group and current_object_group.get('members'):
                    records.append(current_object_group)
                current_object_group = {
                    'name': obj_group_svc_match.group(1),
                    'rule_type': 'object_group',
                    'type': 'service',
                    'protocol': obj_group_svc_match.group(2),
                    'members': [],
                    'line_number': line_number,
                    'raw_text': line
                }
                # Remember service group name
                try:
                    self.known_service_groups.add(obj_group_svc_match.group(1))
                except Exception:
                    pass
                continue
            
            # Parse service-object (inside service object-group)
            if current_object_group and current_object_group['type'] == 'service':
                svc_obj_range = self.patterns['service_object_range'].match(line)
                if svc_obj_range:
                    member = {'protocol': svc_obj_range.group(1), 'port': f"{svc_obj_range.group(2)}-{svc_obj_range.group(3)}"}
                    if member:
                        current_object_group['members'].append(member)
                    continue

                # Support ASA 'port-object' syntax within service object-group (uses group-level protocol)
                po_range = self.patterns['port_object_range'].match(line)
                if po_range:
                    proto = current_object_group.get('protocol')
                    start, end = po_range.group(1), po_range.group(2)
                    member = {'protocol': proto, 'port': f"{start}-{end}"}
                    current_object_group['members'].append(member)
                    continue

                po_eq = self.patterns['port_object_eq'].match(line)
                if po_eq:
                    proto = current_object_group.get('protocol')
                    port_or_name = po_eq.group(1)
                    # Preserve numeric ports vs named services; importer will classify
                    member = {'protocol': proto, 'port': port_or_name}
                    current_object_group['members'].append(member)
                    continue

                svc_obj_match = self.patterns['service_object'].match(line)
                if svc_obj_match:
                    # Support tcp-udp by splitting into two members
                    proto = svc_obj_match.group(1)
                    port = svc_obj_match.group(2)
                    if proto and proto.lower() == 'tcp-udp':
                        current_object_group['members'].append({'protocol': 'tcp', 'port': port})
                        current_object_group['members'].append({'protocol': 'udp', 'port': port})
                    else:
                        member = self._parse_service_object(svc_obj_match)
                        if member:
                            current_object_group['members'].append(member)
                    continue
                elif not raw_line.startswith(' '):
                    # End of object-group
                    if current_object_group['members']:
                        records.append(current_object_group)
                    current_object_group = None

            # Parse plain object network
            obj_net_match = self.patterns['object_network'].match(line)
            if obj_net_match:
                if current_object_group and current_object_group.get('members'):
                    records.append(current_object_group)
                current_object_group = {
                    'name': obj_net_match.group(1),
                    'rule_type': 'object_group',
                    'type': 'network',
                    'members': [],
                    'line_number': line_number,
                    'raw_text': line
                }
                try:
                    self.known_network_groups.add(obj_net_match.group(1))
                except Exception:
                    pass
                continue

            # Lines inside plain object network
            if current_object_group and current_object_group['type'] == 'network':
                host_m = self.patterns['object_host'].match(line)
                subnet_m = self.patterns['object_subnet'].match(line)
                range_m = self.patterns['object_range'].match(line)
                if host_m:
                    current_object_group['members'].append({'type': 'host', 'address': host_m.group(1)})
                    continue
                if subnet_m:
                    current_object_group['members'].append({'type': 'network', 'address': subnet_m.group(1), 'mask': subnet_m.group(2)})
                    continue
                if range_m:
                    current_object_group['members'].append({'type': 'range', 'address': f"{range_m.group(1)}-{range_m.group(2)}"})
                    continue
                elif not raw_line.startswith(' '):
                    if current_object_group.get('members'):
                        records.append(current_object_group)
                    current_object_group = None

            # Parse plain object service
            obj_svc_match = self.patterns['object_service'].match(line)
            if obj_svc_match:
                if current_object_group and current_object_group.get('members'):
                    records.append(current_object_group)
                current_object_group = {
                    'name': obj_svc_match.group(1),
                    'rule_type': 'object_group',
                    'type': 'service',
                    'protocol': None,
                    'members': [],
                    'line_number': line_number,
                    'raw_text': line
                }
                try:
                    self.known_service_groups.add(obj_svc_match.group(1))
                except Exception:
                    pass
                continue

            # Lines inside plain object service
            if current_object_group and current_object_group['type'] == 'service':
                # support ranges in plain object service definitions
                svc_range = re.match(r'^service\s+(tcp|udp|tcp-udp)\s+(?:destination\s+)?range\s+(\d+)\s+(\d+)$', line)
                if svc_range:
                    proto = svc_range.group(1)
                    rng = f"{svc_range.group(2)}-{svc_range.group(3)}"
                    if proto and proto.lower() == 'tcp-udp':
                        current_object_group['members'].append({'protocol': 'tcp', 'port': rng})
                        current_object_group['members'].append({'protocol': 'udp', 'port': rng})
                    else:
                        current_object_group['members'].append({'protocol': proto, 'port': rng})
                    continue
                svc_line = self.patterns['object_service_line'].match(line)
                if svc_line:
                    # Support tcp-udp here as well
                    proto = svc_line.group(1)
                    port = svc_line.group(2)
                    if proto and proto.lower() == 'tcp-udp':
                        current_object_group['members'].append({'protocol': 'tcp', 'port': port})
                        current_object_group['members'].append({'protocol': 'udp', 'port': port})
                    else:
                        current_object_group['members'].append({'protocol': proto, 'port': port})
                    continue
                elif not raw_line.startswith(' '):
                    if current_object_group.get('members'):
                        records.append(current_object_group)
                    current_object_group = None
            
            # Parse NAT rules
            nat_match = self.patterns['nat_rule'].match(line)
            if nat_match:
                record = self._parse_nat_rule(nat_match, line, line_number)
                if record:
                    records.append(record)
                continue
        
        # Handle any remaining object-group
        if current_object_group and current_object_group.get('members'):
            records.append(current_object_group)
        
        # Post-process ACL groups to extract object-group members from expanded lines
        extracted_groups = {}  # (name, type) -> {type, members: set()}

        for key, group in acl_groups.items():
            details = group.get('details', [])
            if not details:
                continue
            
            # Detect Service Object Group in protocol position (ASA specific)
            # Scenario: "access-list ... permit object-group SVC object SRC object-group DST"
            # Parser might see: Proto=ip, Src=SVC, Dst=SRC;DST
            # We fix this by checking if 'source' is an object-group and 'destination' has multiple tokens,
            # and details imply a specific protocol (tcp/udp) not present in parent.
            if (group.get('protocol') == 'ip' and 
                group.get('source', '').lower().startswith('object-group ') and
                ';' in group.get('destination', '')):
                
                # Check expanded details for confirmation
                first_detail = details[0]
                det_proto = first_detail.get('raw_text', '').strip().split()[2] # roughly "permit tcp ..."
                # Or better: check if destination has 2 parts that match expanded src/dst
                
                dst_parts = group['destination'].split(';')
                if len(dst_parts) >= 2:
                    potential_src = dst_parts[0] # "object H_..."
                    potential_dst = dst_parts[1] # "object-group SUBNET..."
                    
                    # Heuristic: If expanded source is in potential_src (or vice versa)
                    # and expanded dest is in potential_dst
                    # and expanded protocol (tcp/udp) is likely from the Service Group
                    
                    # Simple realignment
                    group['protocol'] = group['source'] # "object-group Trend-Micro-Apex"
                    group['source'] = potential_src
                    group['destination'] = potential_dst
                    # Only keep remaining parts if any? For now assume 3-part structure
                    if len(dst_parts) > 2:
                        # Append others? Rare case.
                        pass
                        
            # Helper to extract members for a field
            def extract_members(detail_field, group_type, group_name_field=None):
                if group_name_field is None:
                    group_name_field = detail_field
                
                base_val = group.get(group_name_field)
                if not base_val:
                    return
                
                # Check if base value refers to a group
                base_val_lower = base_val.lower()
                group_name = None
                if base_val_lower.startswith('object-group '):
                    group_name = base_val.split(' ', 1)[1]
                elif base_val_lower.startswith('object '):
                    # In ASA, 'object NAME' can be a network object group (effectively)
                    group_name = base_val.split(' ', 1)[1]
                
                if group_name:
                    group_key = (group_name, group_type)
                    if group_key not in extracted_groups:
                        extracted_groups[group_key] = {'type': group_type, 'members': set()}
                    
                    for det in details:
                        det_val = det.get(detail_field)
                        if det_val:
                            # det_val might be 'host 1.1.1.1', '1.1.1.1', 'range ...', etc.
                            extracted_groups[group_key]['members'].add(det_val)

            extract_members('source', 'network')
            extract_members('destination', 'network')
            
            # Special handling for Service Groups in protocol field
            if group.get('protocol', '').lower().startswith('object-group '):
                # Extract protocol and port from details, associating with the protocol group
                extract_members('protocol', 'service', group_name_field='protocol')
                extract_members('dest_port', 'service', group_name_field='protocol')
            else:
                extract_members('dest_port', 'service')

        # Convert extracted groups to records
        for (name, g_type), data in extracted_groups.items():
            if not data['members']:
                continue
            
            # Convert set of strings to list of member dicts
            members_list = []
            for m in data['members']:
                # Simple heuristic to determine type
                m_lower = m.lower()
                m_type = 'host'
                m_val = m
                if m_lower.startswith('host '):
                    m_type = 'host'
                    m_val = m[5:].strip()
                elif m_lower.startswith('object '): # Nested object
                    m_type = 'object'
                    m_val = m[7:].strip()
                elif m_lower.startswith('range '):
                    m_type = 'range'
                    m_val = m[6:].strip()
                elif '/' in m: # CIDR
                    m_type = 'subnet'
                elif data['type'] == 'service':
                    m_type = 'service' # generic for ports
                
                members_list.append({
                    'type': m_type,
                    'address': m_val, # for network groups
                    'protocol': group.get('protocol') if data['type'] == 'service' else None,
                    'port': m_val if data['type'] == 'service' else None
                })

            records.append({
                'name': name,
                'rule_type': 'object_group',
                'type': data['type'],
                'members': members_list,
                'line_number': 0, # Virtual
                'raw_text': f"Extracted from {group.get('acl_name', 'unknown')} expansion",
                'vendor': 'cisco_asa',
                'source': 'expansion' # Flag to indicate origin
            })

        grouped_list = list(acl_groups.values())
        records.extend(grouped_list)
        
        # Post-process to fix Service Object Group mapping issues
        records = self._post_process_service_groups(records)
        
        return records

    def _post_process_service_groups(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fix mapping for rules where Service Object Group was parsed as Source
        due to missing protocol keyword (implicit protocol group).
        """
        for record in records:
            if record.get('rule_type') != 'access_list':
                continue
                
            # Check for pattern: Protocol=ip, Source=object-group <ServiceGroup>
            # OR Protocol=ip, Source=<ServiceGroup> (implicit object-group)
            if record.get('protocol') == 'ip':
                source_val = record.get('source', '')
                if not source_val:
                    continue

                group_name = None
                is_explicit_og = False

                if source_val.lower().startswith('object-group '):
                    group_name = source_val.split(' ', 1)[1].strip()
                    is_explicit_og = True
                else:
                    # Might be implicit object group name
                    group_name = source_val.strip()

                if group_name:
                    try:
                        # Check if this group is known as a Service group
                        if group_name in self.known_service_groups:
                            # Found it! Remap fields.
                            # Old: Proto=ip, Src=SVC, Dst=SRC;DST (likely merged)
                            # New: Proto=SVC, Src=SRC, Dst=DST
                            
                            # Use explicit object-group syntax for protocol if it was explicit in source,
                            # or if we want to standardize. Let's standardize to "object-group <name>"
                            record['protocol'] = f"object-group {group_name}"
                            
                            # Now unmerge destination
                            # If parser did its job, Dst contains "SRC;DST" or similar
                            dst_val = record.get('destination', '')
                            parts = [p.strip() for p in dst_val.split(';') if p.strip()]
                            
                            if len(parts) >= 2:
                                record['source'] = parts[0]
                                record['destination'] = ';'.join(parts[1:])
                                record['dest_port'] = None 
                            elif len(parts) == 1:
                                record['source'] = parts[0]
                                record['destination'] = 'any'
                            else:
                                # Fallback if destination is empty?
                                record['source'] = 'any'
                                record['destination'] = 'any'
                    except Exception:
                        pass
                        
        return records
    
    def _parse_access_list_rule(self, match: re.Match, raw_line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse access-list rule match"""
        try:
            # Fallback tokenize to ensure multi-token entities (object-group/object/host) are captured fully
            parsed_entities = self._parse_acl_entities_from_raw(raw_line)
            if len(parsed_entities) == 4:
                src_tok, dst_tok, port_tok, proto_tok = parsed_entities
            else:
                src_tok, dst_tok, port_tok = parsed_entities
                proto_tok = None

            destination_combined = dst_tok or 'any'
            dest_port_val = port_tok
            
            # Determine protocol: explicit from token parsing, or 'ip'
            protocol_val = proto_tok or 'ip'
            
            # Check for 'inactive' keyword in raw line
            is_disabled = False
            if 'inactive' in raw_line.lower().split():
                is_disabled = True
            
            # Extract hit count from raw line
            hit_count = 0
            hit_match = re.search(r'\(hitcnt=(\d+)\)', raw_line)
            if hit_match:
                hit_count = int(hit_match.group(1))

            return {
                'rule_type': 'access_list',
                'acl_name': match.group(1),
                'line_number_in_acl': int(match.group(2)) if match.group(2) else None,
                'action': match.group(3),
                'protocol': protocol_val,
                'source': src_tok or 'any',
                'destination': destination_combined,
                'source_port': None,
                'dest_port': dest_port_val,
                'is_disabled': is_disabled,
                'hit_count': hit_count,
                'rule_name': self.current_context.get('rule_name'),
                'raw_text': raw_line,
                'file_line_number': line_number,
                'vendor': 'cisco_asa'
            }
        except Exception as e:
            self.logger.warning(f"Error parsing access-list rule at line {line_number}: {str(e)}")
            return None

    def _parse_acl_entities_from_raw(self, raw_line: str):
        """Parse source, destination, and port from raw ACL text by tokenizing.
        Returns tuple: (source, destination, dest_port, protocol)
        """
        try:
            toks = raw_line.strip().split()
            if not toks:
                return (None, None, None, None)
            
            # 1. Skip standard prefix tokens to find the start of the rule body
            i = 0
            while i < len(toks):
                t = toks[i].lower()
                if t == 'access-list':
                    i += 1
                    if i < len(toks): i += 1 # Skip ACL name
                    continue
                if t == 'line' and i + 1 < len(toks) and toks[i+1].isdigit():
                    i += 2
                    continue
                if t == 'extended':
                    i += 1
                    continue
                if t in ('permit', 'deny'):
                    i += 1
                    # After action, we expect protocol or object-group
                    break
                i += 1

            # 2. Extract Protocol (or Service Object Group acting as protocol)
            proto_hint = None
            dest_port = None
            
            if i < len(toks):
                t = toks[i].lower()
                # Check for explicit protocol
                if t in ('tcp', 'udp', 'icmp', 'ip'):
                    proto_hint = t
                    i += 1
                # Check for object-group as protocol (Service Object Group)
                elif t == 'object-group' and i + 1 < len(toks):
                    # It's likely a service group occupying the protocol slot
                    dest_port = f"object-group {toks[i+1]}"
                    proto_hint = dest_port # Service group implies protocol
                    i += 2
            
            # 3. Extract Source and Destination
            def consume_entity(idx):
                if idx >= len(toks): return (None, idx)
                t = toks[idx].lower()
                if t in ('object-group', 'object', 'host') and idx + 1 < len(toks):
                    return (f"{t} {toks[idx+1]}", idx + 2)
                if t == 'any':
                    return ('any', idx + 1)
                
                # Handle 'range' for IP ranges (source/destination)
                if t == 'range' and idx + 2 < len(toks):
                    # Check if next tokens look like IPs
                    is_ip_range = (re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[idx+1]) and 
                                 re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[idx+2]))
                    if is_ip_range:
                        return (f"range {toks[idx+1]} {toks[idx+2]}", idx + 3)

                # IP Mask detection
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
                    if idx + 1 < len(toks) and re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[idx+1]):
                        return (f"{t} {toks[idx+1]}", idx + 2)
                    return (t, idx + 1)
                return (t, idx + 1)

            src, i = consume_entity(i)
            dst, i = consume_entity(i)
            
            # 4. Extract Extras (Destinations, Ports, Ranges)
            extras = []
            
            while i < len(toks):
                t = toks[i].lower()
                
                # Handle 'eq' port
                if t == 'eq' and i + 1 < len(toks):
                    val = toks[i+1]
                    dest_port = f"{dest_port},{val}" if dest_port else val
                    i += 2
                    continue
                
                # Handle 'range'
                if t == 'range' and i + 2 < len(toks):
                    # Check if IP range (destination)
                    is_ip_range = (re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[i+1]) and 
                                 re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[i+2]))
                    if is_ip_range:
                         extras.append(f"range {toks[i+1]} {toks[i+2]}")
                         i += 3
                         continue

                    # Assume port range
                    rng = f"{toks[i+1]}-{toks[i+2]}"
                    dest_port = f"{dest_port},{rng}" if dest_port else rng
                    i += 3
                    continue
                
                # Handle ICMP types
                if proto_hint == 'icmp' and t in ('echo', 'echo-reply', 'time-exceeded', 'unreachable'):
                     dest_port = toks[i]
                     i += 1
                     continue

                # Handle extra destinations (object-group, object, host)
                if t in ('object-group', 'object', 'host'):
                    ent, i = consume_entity(i)
                    if ent: extras.append(ent)
                    continue
                
                i += 1

            # 5. Heuristic Post-Processing (Fix Source/Port shifts)
            # If dest_port is missing (or matched as src), check if src looks like a service group
            def is_service_group_name(name):
                if not name: return False
                nl = name.lower()
                # Common service group indicators
                return 'port' in nl or 'tcp' in nl or 'udp' in nl or 'service' in nl or 'svc' in nl

            # If we didn't find a dest_port/protocol earlier, but src looks like one, shift it.
            # Also, if we found a protocol (e.g. 'ip') but src is a service object group, it might be the 'implicit' case.
            # E.g. "permit ip object-group SVC_GRP ..." -> actually SVC_GRP is the service/port
            
            src_name = src.split()[-1] if src and ' ' in src else src
            
            should_shift = False
            if not dest_port:
                if is_service_group_name(src_name):
                    should_shift = True
                # Also check known service groups if available
                elif hasattr(self, 'known_service_groups') and src_name in self.known_service_groups:
                    should_shift = True
            
            if should_shift:
                dest_port = src
                if not proto_hint or proto_hint == 'ip':
                    proto_hint = dest_port
                
                # Shift src <- dst, dst <- extra[0]
                src = dst
                if extras:
                    dst = extras.pop(0)
                else:
                    dst = 'any' # Or None, but 'any' is safer for normalization
            
            # 6. Deduplicate Destinations
            all_dsts = []
            if dst: all_dsts.append(dst)
            if extras: all_dsts.extend(extras)
            
            unique_dsts = []
            seen = set()
            for d in all_dsts:
                if d not in seen:
                    unique_dsts.append(d)
                    seen.add(d)
            
            dst_full = ';'.join(unique_dsts) if unique_dsts else None
            
            return (src, dst_full, dest_port, proto_hint)
            
        except Exception as e:
            self.logger.warning(f"Error tokenizing ACL rule: {e}")
            return (None, None, None, None)
    
    def _parse_network_object(self, match: re.Match) -> Optional[Dict[str, Any]]:
        """Parse network-object match"""
        try:
            is_host = match.group(1) is not None
            address = match.group(2)
            mask = match.group(3)
            
            return {
                'type': 'host' if is_host else 'network',
                'address': address,
                'mask': mask if not is_host else None
            }
        except Exception as e:
            self.logger.warning(f"Error parsing network object: {str(e)}")
            return None
    
    def _parse_service_object(self, match: re.Match) -> Optional[Dict[str, Any]]:
        """Parse service-object match"""
        try:
            return {
                'protocol': match.group(1),
                'port': match.group(2)
            }
        except Exception as e:
            self.logger.warning(f"Error parsing service object: {str(e)}")
            return None
    
    def _parse_nat_rule(self, match: re.Match, raw_line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse NAT rule match"""
        try:
            return {
                'rule_type': 'nat',
                'inside_interface': match.group(1),
                'outside_interface': match.group(2),
                'nat_id': int(match.group(3)),
                'translation_type': match.group(4),
                'real_source': match.group(5),
                'mapped_source': match.group(6),
                'dest_translation_type': match.group(7),
                'real_destination': match.group(8),
                'mapped_destination': match.group(9),
                'raw_text': raw_line,
                'file_line_number': line_number,
                'vendor': 'cisco_asa'
            }
        except Exception as e:
            self.logger.warning(f"Error parsing NAT rule at line {line_number}: {str(e)}")
            return None
    
    def _parse_palo_alto(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse Palo Alto configuration (placeholder)
        
        Args:
            content: File content
            
        Returns:
            List of parsed records
        """
        # Placeholder for Palo Alto parsing
        self.logger.info("Palo Alto parsing not yet implemented")
        return []
    
    def _parse_fortinet(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse Fortinet configuration (placeholder)
        
        Args:
            content: File content
            
        Returns:
            List of parsed records
        """
        # Placeholder for Fortinet parsing
        self.logger.info("Fortinet parsing not yet implemented")
        return []
    
    def _parse_generic(self, content: str) -> List[Dict[str, Any]]:
        """
        Generic parsing for unknown vendors
        
        Args:
            content: File content
            
        Returns:
            List of parsed records
        """
        records = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue

            parsed = self._parse_generic_rule_line(line)
            if parsed:
                parsed['file_line_number'] = i
                parsed['vendor'] = 'unknown'
                records.append(parsed)
            else:
                records.append({
                    'rule_type': 'generic',
                    'raw_text': line,
                    'file_line_number': i,
                    'vendor': 'unknown'
                })
        
        return records
    
    def _clean_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Clean and standardize firewall records
        
        Args:
            records: Raw records
            
        Returns:
            Cleaned records
        """
        cleaned_records = []
        
        for record in records:
            try:
                cleaned_record = self._clean_single_record(record)
                if cleaned_record:
                    cleaned_records.append(cleaned_record)
            except Exception as e:
                self.logger.warning(f"Error cleaning record: {str(e)}")
        
        return cleaned_records
    
    def _clean_single_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Clean a single firewall record
        
        Args:
            record: Record to clean
            
        Returns:
            Cleaned record or None if invalid
        """
        if not record.get('raw_text'):
            return None
        
        cleaned = {}
        
        for key, value in record.items():
            if value is not None:
                if isinstance(value, str):
                    cleaned_value = value.strip()
                    if cleaned_value:
                        cleaned[key] = cleaned_value
                else:
                    cleaned[key] = value
        
        return cleaned if cleaned else None
    
    def get_supported_vendors(self) -> List[str]:
        """Get list of supported vendors"""
        return ['cisco_asa', 'palo_alto', 'fortinet']
    
    def detect_vendor(self, content: str) -> str:
        """
        Attempt to detect vendor from configuration content
        
        Args:
            content: Configuration file content
            
        Returns:
            Detected vendor or 'unknown'
        """
        content_lower = content.lower()
        
        # Cisco ASA indicators
        if any(indicator in content_lower for indicator in [
            'access-list', 'object-group', 'asa version', 'ciscoasa'
        ]):
            return 'cisco_asa'
        
        # Palo Alto indicators
        if any(indicator in content_lower for indicator in [
            'set rulebase', 'set deviceconfig', 'palo alto'
        ]):
            return 'palo_alto'
        
        # Fortinet indicators
        if any(indicator in content_lower for indicator in [
            'config firewall', 'fortigate', 'fortios'
        ]):
            return 'fortinet'
        
        return 'unknown'
    def _extract_rule_name_from_remark(self, remark: str) -> str:
        m = re.search(r'(CMR[\w\-_/]+)', remark, re.IGNORECASE)
        if m:
            return m.group(1)
        m2 = re.search(r'(CHG[\w\-_/]+)', remark, re.IGNORECASE)
        if m2:
            return m2.group(1)
        return remark.strip()
    def _parse_generic_rule_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Heuristically parse a generic firewall rule line."""
        # Common patterns
        patterns = [
            # permit tcp any 10.0.0.5 eq 80
            re.compile(r"\b(permit|allow|deny|block)\b\s+(tcp|udp|icmp|ip|any)\s+(\S+)\s+(\S+)(?:\s+(?:eq|port)\s*(\S+))?", re.IGNORECASE),
            # allow from 10.0.0.1 to 10.0.0.2 port 443
            re.compile(r"\b(permit|allow|deny|block)\b.*?from\s+(\S+)\s+to\s+(\S+).*?(?:port\s*(\d+)|eq\s*(\S+))", re.IGNORECASE),
            # Rule: Allow TCP 172.16.0.0/16 -> 10.0.0.5:443
            re.compile(r"\b(permit|allow|deny|block)\b\s+(tcp|udp|icmp|ip|any)\s+(\S+)\s*(?:->|to)\s*(\S+?)(?::(\d+))?$", re.IGNORECASE),
        ]

        for pat in patterns:
            m = pat.search(line)
            if m:
                groups = [g for g in m.groups()]
                # Normalize mapping across different patterns
                action = groups[0]
                # Determine positions for protocol/source/dest/port depending on pattern matched
                if pat == patterns[0]:
                    protocol = groups[1]
                    source = groups[2]
                    destination = groups[3]
                    port = groups[4]
                elif pat == patterns[1]:
                    protocol = None
                    source = groups[1]
                    destination = groups[2]
                    port = groups[3] or groups[4]
                else:
                    protocol = groups[1]
                    source = groups[2]
                    destination = groups[3]
                    port = groups[4]

                return {
                    'rule_type': 'access_list',
                    'action': action,
                    'protocol': protocol or 'ip',
                    'source': source or 'any',
                    'destination': destination or 'any',
                    'dest_port': port,
                    'raw_text': line,
                }

        # Token-based fallback
        tokens = line.split()
        action = next((t for t in tokens if t.lower() in ('permit','allow','deny','block')), None)
        protocol = next((t for t in tokens if t.lower() in ('tcp','udp','icmp','ip','any')), None)
        # Find 'from X to Y'
        source = None
        destination = None
        for idx, t in enumerate(tokens):
            if t.lower() == 'from' and idx+2 < len(tokens):
                source = tokens[idx+1]
                if tokens[idx+2].lower() == 'to' and idx+3 < len(tokens):
                    destination = tokens[idx+3]
                break
        # Fallback using arrow
        if not source and '->' in line:
            parts = [p.strip() for p in line.split('->', 1)]
            if len(parts) == 2:
                source = source or parts[0].split()[-1]
                destination = destination or parts[1].split()[0]

        # Extract port after 'port' or 'eq' or ':' suffix
        port = None
        for idx, t in enumerate(tokens):
            if t.lower() in ('port','eq') and idx+1 < len(tokens):
                port = tokens[idx+1]
                break
        if not port and ':' in line:
            maybe_port = line.rsplit(':', 1)[-1]
            if maybe_port.isdigit():
                port = maybe_port

        if action or protocol or source or destination or port:
            return {
                'rule_type': 'access_list',
                'action': action,
                'protocol': protocol,
                'source': source,
                'destination': destination,
                'dest_port': port,
                'raw_text': line,
            }
        return None
