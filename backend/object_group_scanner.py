"""
Object Group Scanner

This script scans the raw_firewall_rules table to identify object group references
using regex patterns and stores them in the object_groups table with 'unresolved' status.
"""

import re
import logging
from typing import Set, List, Dict, Any
from sqlalchemy.orm import Session
from models import RawFirewallRule, ObjectGroup, db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ObjectGroupScanner:
    """Scanner to identify object groups from raw firewall rules"""
    
    def __init__(self):
        # Regex patterns to identify object groups
        # Common patterns: OBJ-*, GRP-*, *-GRP, *-OBJ, etc.
        self.object_group_patterns = [
            r'\b(OBJ-[A-Za-z0-9_-]+)\b',           # OBJ-WEB-SERVERS
            r'\b(GRP-[A-Za-z0-9_-]+)\b',           # GRP-WEB-SERVERS
            r'\b([A-Za-z0-9_]+-OBJ)\b',            # WEB-SERVERS-OBJ
            r'\b([A-Za-z0-9_]+-GRP)\b',            # WEB-SERVERS-GRP
            r'\b(GROUP_[A-Za-z0-9_-]+)\b',         # GROUP_WEB_SERVERS
            r'\b([A-Za-z0-9_]+-GROUP)\b',          # WEB-SERVERS-GROUP
            r'\b(NET-[A-Za-z0-9_-]+)\b',           # NET-DMZ-SERVERS
            r'\b(SVC-[A-Za-z0-9_-]+)\b',           # SVC-WEB-SERVICES
            r'\b(HOST-[A-Za-z0-9_-]+)\b',          # HOST-WEB-CLUSTER
            # ASA style references
            r'\bobject-group\s+(?:network|service)\s+([A-Za-z0-9_-]+)\b',
            r'\bobject-group\s+([A-Za-z0-9_-]+)\b',
        ]
        
        # Compile patterns for better performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.object_group_patterns]

    # Fallback heuristics: treat non-IP textual tokens in source/destination as candidate groups
    def _is_ip_or_cidr(self, token: str) -> bool:
        ipv4 = re.compile(r'^((25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.){3}(25[0-5]|2[0-4]\d|[0-1]?\d?\d))(\/([0-2]?\d|3[0-2]))?$')
        ipv6 = re.compile(r'^[0-9a-fA-F:]+(\/\d{1,3})?$')
        return bool(ipv4.match(token) or ipv6.match(token))

    def _is_reserved_word(self, token: str) -> bool:
        reserved = {
            'any','host','eq','lt','gt','object','group','object-group','interface',
            'permit','deny','ip','tcp','udp','icmp','source','destination','addr','address',
            'netmask','subnet','range','time-range','security-level','service','port',
            'access-list'
        }
        return token.lower() in reserved

    def _extract_candidates_by_non_ip_tokens(self, text: str) -> Set[str]:
        candidates = set()
        if not text:
            return candidates
        # Split only on comma/semicolon/newline, not on spaces, so names
        # containing spaces remain intact. The user data uses ',' as the
        # primary delimiter between multiple objects in a field.
        segments = re.split(r'[,\n;]+', text)
        def _is_ip_range(tok: str) -> bool:
            if '-' in tok:
                parts = tok.split('-')
                if len(parts) == 2 and self._is_ip_or_cidr(parts[0]) and self._is_ip_or_cidr(parts[1]):
                    return True
            return False
        for raw in segments:
            t = raw.strip()
            if not t:
                continue
            # Skip IPs/CIDRs, pure numbers, IP ranges, and reserved words
            if self._is_ip_or_cidr(t) or t.isdigit() or _is_ip_range(t) or self._is_reserved_word(t):
                continue
            # Heuristic: likely group names have '-' or '_' or mixed case and length
            if ('-' in t or '_' in t or re.search(r'[A-Z].*[a-z]|[a-z].*[A-Z]', t)) and len(t) >= 4:
                candidates.add(t)
        return candidates

    def extract_object_groups_from_text(self, text: str, allow_fallback: bool = True) -> Set[str]:
        """Extract object group names from a text string"""
        if not text:
            return set()
        
        object_groups = set()
        
        for pattern in self.compiled_patterns:
            matches = pattern.findall(text)
            if not matches:
                continue
            if isinstance(matches[0], tuple):
                for m in matches:
                    for part in reversed(m):
                        if part:
                            object_groups.add(part)
                            break
            else:
                for m in matches:
                    object_groups.add(m)
        
        if allow_fallback:
            object_groups.update(self._extract_candidates_by_non_ip_tokens(text))
        # Final cleanup: remove reserved tokens accidentally matched
        object_groups = {g for g in object_groups if not self._is_reserved_word(g)}
        return object_groups

    def scan_raw_firewall_rules(self, source_file: str = None) -> Dict[str, Any]:
        """
        Scan raw firewall rules and identify object groups
        """
        try:
            # Query raw firewall rules
            query = db.session.query(RawFirewallRule)
            if source_file:
                query = query.filter(RawFirewallRule.source_file == source_file)
            rules = query.all()
            logger.info(f"Scanning {len(rules)} raw firewall rules for object groups")
            discovered_groups = {}
            total_groups_found = 0
            for rule in rules:
                # Only scan source and destination per requirements
                fields_to_scan = [
                    ('source', rule.source, True),
                    ('destination', rule.destination, True),
                ]
                for field_name, field_value, allow_fallback in fields_to_scan:
                    if not field_value:
                        continue
                    groups_in_field = self.extract_object_groups_from_text(str(field_value), allow_fallback=allow_fallback)
                    for group_name in groups_in_field:
                        if group_name not in discovered_groups:
                            discovered_groups[group_name] = {
                                'name': group_name,
                                'group_type': self.determine_group_type(group_name),
                                'source_files': set(),
                                'found_in_fields': set(),
                                'rule_count': 0
                            }
                        discovered_groups[group_name]['source_files'].add(rule.source_file)
                        discovered_groups[group_name]['found_in_fields'].add(field_name)
                        discovered_groups[group_name]['rule_count'] += 1
                        total_groups_found += 1
            logger.info(f"Found {len(discovered_groups)} unique object groups in {total_groups_found} references")
            new_groups_count = 0
            updated_groups_count = 0
            for group_name, group_info in discovered_groups.items():
                existing_group = db.session.query(ObjectGroup).filter_by(name=group_name).first()
                if existing_group:
                    if existing_group.status == 'unresolved':
                        existing_group.description = f"Found in fields: {', '.join(group_info['found_in_fields'])}"
                        updated_groups_count += 1
                else:
                    new_group = ObjectGroup(
                        name=group_name,
                        group_type=group_info['group_type'],
                        source_file=list(group_info['source_files'])[0] if group_info['source_files'] else 'unknown',
                        description=f"Auto-discovered object group. Found in fields: {', '.join(group_info['found_in_fields'])}",
                        status='unresolved',
                        vendor='auto-detected'
                    )
                    db.session.add(new_group)
                    new_groups_count += 1
            db.session.commit()
            scan_results = {
                'total_rules_scanned': len(rules),
                'unique_groups_found': len(discovered_groups),
                'total_group_references': total_groups_found,
                'new_groups_created': new_groups_count,
                'existing_groups_updated': updated_groups_count,
                'groups_by_type': {},
                'groups_detail': []
            }
            for group_info in discovered_groups.values():
                scan_results['groups_detail'].append({
                    'name': group_info['name'],
                    'group_type': group_info['group_type'],
                    'source_files': list(group_info['source_files']),
                    'found_in_fields': list(group_info['found_in_fields']),
                    'rule_count': group_info['rule_count']
                })
            for group_info in discovered_groups.values():
                gt = group_info['group_type']
                if gt not in scan_results['groups_by_type']:
                    scan_results['groups_by_type'][gt] = 0
                scan_results['groups_by_type'][gt] += 1
            logger.info(f"Scan completed: {new_groups_count} new groups, {updated_groups_count} updated")
            return scan_results
        except Exception as e:
            logger.error(f"Error during object group scan: {str(e)}")
            db.session.rollback()
            raise
    
    def get_unresolved_groups(self) -> List[ObjectGroup]:
        """Get all unresolved object groups"""
        return db.session.query(ObjectGroup).filter_by(status='unresolved').all()
    
    def mark_group_resolved(self, group_id: int) -> bool:
        """Mark an object group as resolved"""
        try:
            group = db.session.query(ObjectGroup).get(group_id)
            if group:
                group.status = 'resolved'
                db.session.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Error marking group as resolved: {str(e)}")
            db.session.rollback()
            return False

    def determine_group_type(self, group_name: str) -> str:
        """Determine the type of object group based on its name"""
        group_name_upper = group_name.upper()
        
        # Network/Host groups
        if any(keyword in group_name_upper for keyword in ['NET', 'HOST', 'SERVER', 'CLIENT', 'DMZ', 'LAN', 'WAN', 'VLAN', 'NETWORK']):
            return 'network'
        
        # Service groups
        if any(keyword in group_name_upper for keyword in ['SVC', 'SERVICE', 'PORT', 'PROTOCOL', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS']):
            return 'service'
        
        # Application groups
        if any(keyword in group_name_upper for keyword in ['APP', 'APPLICATION', 'WEB', 'DB', 'DATABASE', 'API']):
            return 'application'
        
        # Default to network if unclear
        return 'network'

def scan_for_object_groups(source_file: str = None) -> Dict[str, Any]:
    """
    Convenience function to scan for object groups
    
    Args:
        source_file: Optional filter to scan rules from specific file
        
    Returns:
        Dictionary with scan results
    """
    scanner = ObjectGroupScanner()
    return scanner.scan_raw_firewall_rules(source_file)

if __name__ == "__main__":
    # Run scanner when script is executed directly
    print("Starting object group scan...")
    results = scan_for_object_groups()
    
    print("\n=== Object Group Scan Results ===")
    print(f"Rules scanned: {results['total_rules_scanned']}")
    print(f"Unique groups found: {results['unique_groups_found']}")
    print(f"Total group references: {results['total_group_references']}")
    print(f"New groups created: {results['new_groups_created']}")
    print(f"Existing groups updated: {results['existing_groups_updated']}")
    
    print("\nGroups by type:")
    for group_type, count in results['groups_by_type'].items():
        print(f"  {group_type}: {count}")
    
    print("\nScan completed successfully!")
