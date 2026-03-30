"""
Protocol/Port Parser Utility

This module provides functions to parse combined protocol/port fields
commonly found in firewall rule CSV files.

Supported formats:
- TCP/80, UDP/53, ICMP/0
- tcp/443, udp/161
- TCP:80, UDP:53
- 80/TCP, 53/UDP (reverse format)

Enhanced with service mapping API integration for better service name resolution.
"""

import re
import requests
from typing import Tuple, Optional, Dict, List
from functools import lru_cache
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Service mapping API configuration
SERVICE_MAPPING_API_BASE = "http://localhost:5001/api"


@lru_cache(maxsize=1000)
def lookup_service_by_port(port_number: int, protocol: Optional[str] = None) -> List[Dict]:
    """
    Lookup service names by port number using the service mapping API.
    
    Args:
        port_number (int): The port number to lookup
        protocol (str, optional): The protocol (tcp/udp) to filter by
        
    Returns:
        List[Dict]: List of service mappings for the port
    """
    try:
        url = f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{port_number}"
        params = {}
        if protocol:
            params['protocol'] = protocol.lower()
        
        response = requests.get(url, params=params, timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('services', [])
        else:
            logger.debug(f"No service mapping found for port {port_number}")
            return []
    except Exception as e:
        logger.debug(f"Error looking up service for port {port_number}: {str(e)}")
        return []


@lru_cache(maxsize=1000)
def lookup_port_by_service(service_name: str) -> Optional[Dict]:
    """
    Lookup port information by service name using the service mapping API.
    
    Args:
        service_name (str): The service name to lookup
        
    Returns:
        Dict or None: Service mapping information or None if not found
    """
    try:
        url = f"{SERVICE_MAPPING_API_BASE}/service-mappings/lookup/{service_name}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('found'):
                return data.get('mapping')
        return None
    except Exception as e:
        logger.debug(f"Error looking up port for service {service_name}: {str(e)}")
        return None


def get_service_name_for_port(port_number: int, protocol: Optional[str] = None) -> Optional[str]:
    """
    Get the primary service name for a given port and protocol.
    
    Args:
        port_number (int): The port number
        protocol (str, optional): The protocol (tcp/udp)
        
    Returns:
        str or None: The primary service name or None if not found
    """
    services = lookup_service_by_port(port_number, protocol)
    if services:
        # Return the first well-known service, or the first service if none are well-known
        well_known_services = [s for s in services if s.get('is_well_known', False)]
        if well_known_services:
            return well_known_services[0]['service_name']
        return services[0]['service_name']
    return None


def parse_protocol_port(combined_field: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a combined protocol/port field into separate protocol and port values.
    
    Args:
        combined_field (str): The combined field (e.g., "TCP/80", "UDP/53")
        
    Returns:
        Tuple[Optional[str], Optional[str]]: (protocol, port) or (None, None) if parsing fails
        
    Examples:
        >>> parse_protocol_port("TCP/80")
        ('TCP', '80')
        >>> parse_protocol_port("UDP/53")
        ('UDP', '53')
        >>> parse_protocol_port("ICMP/0")
        ('ICMP', '0')
        >>> parse_protocol_port("80/TCP")
        ('TCP', '80')
    """
    if not combined_field or not isinstance(combined_field, str):
        return None, None
    
    # Clean the input
    field = combined_field.strip().upper()
    
    # Pattern 1: PROTOCOL/PORT (e.g., TCP/80, UDP/53)
    match = re.match(r'^([A-Z]+)[/:](\d+)$', field)
    if match:
        protocol, port = match.groups()
        return protocol, port
    
    # Pattern 2: PORT/PROTOCOL (e.g., 80/TCP, 53/UDP)
    match = re.match(r'^(\d+)[/:]([A-Z]+)$', field)
    if match:
        port, protocol = match.groups()
        return protocol, port
    
    # Pattern 3: Just protocol (e.g., TCP, UDP, ICMP)
    if re.match(r'^[A-Z]+$', field):
        return field, None
    
    # Pattern 4: Just port (e.g., 80, 443, 53)
    if re.match(r'^\d+$', field):
        return None, field
    
    # Pattern 5: Protocol with port range (e.g., TCP/80-90)
    match = re.match(r'^([A-Z]+)[/:](\d+-\d+)$', field)
    if match:
        protocol, port_range = match.groups()
        return protocol, port_range
    
    # Pattern 6: PROTOCOL-PORT (e.g., TCP-80, UDP-53) - dash format
    match = re.match(r'^([A-Z]+)-(\d+)$', field)
    if match:
        protocol, port = match.groups()
        return protocol, port
    
    # Pattern 7: PROTOCOL-PORT-RANGE (e.g., TCP-80-90) - dash format with range
    match = re.match(r'^([A-Z]+)-(\d+-\d+)$', field)
    if match:
        protocol, port_range = match.groups()
        return protocol, port_range

    # Pattern 7b: PROTOCOL_PORT with underscore (e.g., TCP_443, UDP_53)
    match = re.match(r'^([A-Z]+)_(\d+)$', field)
    if match:
        protocol, port = match.groups()
        return protocol, port

    # Pattern 7c: PROTOCOL_PORT_RANGE with underscore (e.g., UDP_16500-16509)
    match = re.match(r'^([A-Z]+)_(\d+-\d+)$', field)
    if match:
        protocol, port_range = match.groups()
        return protocol, port_range

    # Pattern 8: PROTOCOL/SERVICE-NAME (e.g., TCP/LDAP, TCP/SMTP)
    match = re.match(r'^([A-Z]+)[/:]([A-Z][A-Z0-9_-]+)$', field)
    if match:
        protocol, service_name = match.groups()
        # Try service mapping API first
        mapping = lookup_port_by_service(service_name)
        if mapping:
            return protocol, str(mapping.get('port_number'))
        # Fallback mappings
        fallback = {
            'LDAP': '389',
            'SMTP': '25',
            'NETBIOS-SSN': '139',
            'HTTPS': '443',
            'HTTP': '80',
            'DNS': '53',
            'RDP': '3389',
            'REMOTE_DESKTOP_PROTOCOL': '3389',
            'TRACEROUTE': '33434-33534',
            'MICROSOFT-DS': '445',
            'NBSESSION': '139',
            'CPM': '19009',
            'CPMI': '18190'
        }
        if service_name in fallback:
            return protocol, fallback[service_name]
        # If not found, return protocol with None port; caller may treat as literal
        return protocol, None
    
    # If no pattern matches, return as-is for protocol, None for port
    return field, None


def parse_service_field(service_field: str) -> dict:
    """
    Parse a service field that might contain protocol, port, or both.
    Enhanced with service mapping API integration for better service name resolution.
    
    Args:
        service_field (str): The service field value
        
    Returns:
        dict: Dictionary with 'protocol', 'port', and 'service_name' keys
        
    Examples:
        >>> parse_service_field("TCP/80")
        {'protocol': 'TCP', 'port': '80', 'service_name': 'HTTP'}
        >>> parse_service_field("HTTP")
        {'protocol': 'TCP', 'port': '80', 'service_name': 'HTTP'}
    """
    protocol, port = parse_protocol_port(service_field)
    
    # Fallback service mappings for when API is unavailable
    fallback_service_mappings = {
        'HTTP': {'protocol': 'TCP', 'port': '80'},
        'HTTPS': {'protocol': 'TCP', 'port': '443'},
        'SSH': {'protocol': 'TCP', 'port': '22'},
        'FTP': {'protocol': 'TCP', 'port': '21'},
        'TELNET': {'protocol': 'TCP', 'port': '23'},
        'SMTP': {'protocol': 'TCP', 'port': '25'},
        'DNS': {'protocol': 'UDP', 'port': '53'},
        'DHCP': {'protocol': 'UDP', 'port': '67'},
        'TFTP': {'protocol': 'UDP', 'port': '69'},
        'SNMP': {'protocol': 'UDP', 'port': '161'},
        'PING': {'protocol': 'ICMP', 'port': '0'},
        'ICMP': {'protocol': 'ICMP', 'port': '0'},
        'NETBIOS-SSN': {'protocol': 'TCP', 'port': '139'},
        'LDAP': {'protocol': 'TCP', 'port': '389'},
        'RDP': {'protocol': 'TCP', 'port': '3389'},
        'REMOTE DESKTOP': {'protocol': 'TCP', 'port': '3389'},
        'REMOTE_DESKTOP_PROTOCOL': {'protocol': 'TCP', 'port': '3389'},
        'MS-RDP': {'protocol': 'TCP', 'port': '3389'},
        'ICMP-PROTO': {'protocol': 'ICMP', 'port': '0'},
        'TRACEROUTE': {'protocol': 'UDP', 'port': '33434-33534'},
        'MICROSOFT-DS': {'protocol': 'TCP', 'port': '445'},
        'NBSESSION': {'protocol': 'TCP', 'port': '139'},
        'NFS': {'protocol': 'TCP', 'port': '2049'},
        'NFSD': {'protocol': 'TCP', 'port': '2049'},
        'NFSD-TCP': {'protocol': 'TCP', 'port': '2049'},
        'RPCBIND': {'protocol': 'TCP', 'port': '111'},
        'SUNRPC': {'protocol': 'TCP', 'port': '111'},
        'PORTMAP': {'protocol': 'TCP', 'port': '111'},
        'CPM': {'protocol': 'TCP', 'port': '19009'},
        'CPMI': {'protocol': 'TCP', 'port': '18190'}
    }
    
    result = {'protocol': protocol, 'port': port, 'service_name': None}
    
    # If we have a port, try to get the service name from API
    if port and port.isdigit():
        try:
            port_num = int(port)
            service_name = get_service_name_for_port(port_num, protocol)
            if service_name:
                result['service_name'] = service_name
        except (ValueError, TypeError):
            pass
            
    # If service_name is still None but we have a valid port, try to recover the name from input
    if result['service_name'] is None and result['port']:
        sf_clean = service_field.strip().upper()
        # Pattern: PROTOCOL/NAME
        if '/' in sf_clean:
            parts = sf_clean.split('/', 1)
            p1, p2 = parts[0].strip(), parts[1].strip()
            if result.get('protocol') and p1 == result['protocol'] and not p2.replace('-','').isdigit():
                result['service_name'] = parts[1].strip()
            elif result.get('protocol') and p2 == result['protocol'] and not p1.replace('-','').isdigit():
                result['service_name'] = parts[0].strip()
        # Pattern: Just NAME (e.g. HTTPS) or NAME-PROTOCOL
        elif sf_clean not in ('TCP','UDP','ICMP','IP') and not re.match(r'^[A-Z]+[-_]\d+$', sf_clean):
             if not sf_clean.replace('-','').isdigit():
                 result['service_name'] = service_field.strip()

    # If we couldn't parse protocol/port, check if it's a known service name
    if protocol is None and port is None:
        service_name = service_field.strip().upper()
        # Normalize vendor-style prefixes like "service-http" -> "HTTP"
        if service_name.startswith('SERVICE-'):
            service_name = service_name[8:]
        if service_name.endswith('-TCP'):
            service_name = service_name[:-4]
        elif service_name.endswith('-UDP'):
            service_name = service_name[:-4]
        
        # First try the API
        service_mapping = lookup_port_by_service(service_name)
        if service_mapping:
            result['protocol'] = service_mapping['protocol'].upper()
            result['port'] = str(service_mapping['port_number'])
            result['service_name'] = service_mapping['service_name']
        # Fallback to hardcoded mappings
        elif service_name in fallback_service_mappings:
            mapping = fallback_service_mappings[service_name]
            result['protocol'] = mapping['protocol']
            result['port'] = mapping['port']
            result['service_name'] = service_name
        else:
            # If no mapping found, treat as protocol
            result['protocol'] = service_name
    # If we only have protocol but no port, check if protocol is actually a service name
    elif protocol and not port:
        service_name = protocol.upper()
        if service_name.startswith('SERVICE-'):
            service_name = service_name[8:]
        if service_name.endswith('-TCP'):
            service_name = service_name[:-4]
        elif service_name.endswith('-UDP'):
            service_name = service_name[:-4]
        
        # First try the API
        service_mapping = lookup_port_by_service(service_name)
        if service_mapping:
            result['protocol'] = service_mapping['protocol'].upper()
            result['port'] = str(service_mapping['port_number'])
            result['service_name'] = service_mapping['service_name']
        # Fallback to hardcoded mappings
        elif service_name in fallback_service_mappings:
            mapping = fallback_service_mappings[service_name]
            result['protocol'] = mapping['protocol']
            result['port'] = mapping['port']
            result['service_name'] = service_name
    
    return result


def get_port_with_service_info(port: str, protocol: Optional[str] = None) -> Dict[str, Optional[str]]:
    """
    Get enhanced port information including service name.
    
    Args:
        port (str): The port number or range
        protocol (str, optional): The protocol (tcp/udp)
        
    Returns:
        Dict: Dictionary with 'port', 'service_name', and 'display' keys
    """
    if not port:
        return {'port': None, 'service_name': None, 'display': None}
    
    # Handle port ranges
    if '-' in str(port):
        return {'port': str(port), 'service_name': None, 'display': str(port)}
    
    # Try to get service name for single port
    try:
        port_num = int(port)
        service_name = get_service_name_for_port(port_num, protocol)
        if service_name:
            display = f"{port} ({service_name})"
        else:
            display = str(port)
        
        return {
            'port': str(port),
            'service_name': service_name,
            'display': display
        }
    except (ValueError, TypeError):
        return {'port': str(port), 'service_name': None, 'display': str(port)}


def parse_ports_with_services(protocol_field: str) -> List[Dict[str, Optional[str]]]:
    """
    Parse a protocol field that may contain multiple ports and return with service names.
    
    Args:
        protocol_field (str): Protocol field that may contain multiple services (e.g., "TCP-80;UDP-53")
        
    Returns:
        List[Dict]: List of port information with service names
    """
    if not protocol_field:
        return []
    
    ports_info = []
    parts = protocol_field.split(';')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        # Parse the individual service
        parsed = parse_service_field(part)
        if parsed.get('port'):
            port_info = get_port_with_service_info(
                parsed['port'], 
                parsed.get('protocol')
            )
            if port_info['port'] and port_info not in ports_info:
                ports_info.append(port_info)
    
    return ports_info


def enhance_row_with_protocol_port(row: dict, service_column: str = 'service', *, allow_protocol: bool = True, allow_dest_port: bool = True) -> dict:
    """
    Enhance a CSV row by parsing combined protocol/port fields.
    
    Args:
        row (dict): The CSV row dictionary
        service_column (str): The column name containing the combined service data
        
    Returns:
        dict: Enhanced row with separate 'protocol' and 'port' fields
    """
    enhanced_row = row.copy()
    
    if service_column in row and row[service_column]:
        value = row[service_column]
        from protocol_port_parser import resolve_protocol_port_from_mixed_field
        resolved = resolve_protocol_port_from_mixed_field(str(value))
        # Prefer resolved protocol if current is missing/invalid
        current_protocol = str(enhanced_row.get('protocol') or '').upper()
        invalid_protocols = {'', 'ANY', 'ALLOW'}
        if allow_protocol and (not current_protocol or current_protocol in invalid_protocols) and resolved.get('protocol'):
            enhanced_row['protocol'] = resolved['protocol']
        # Merge resolved ports with any existing dest_port/source_port
        resolved_ports = str(resolved.get('dest_port') or '').strip()
        if allow_dest_port and resolved_ports:
            # Determine target field
            target_field = 'dest_port'
            if 'source_port' in enhanced_row and not str(enhanced_row.get('source_port') or '').strip():
                target_field = 'source_port'
            existing = str(enhanced_row.get(target_field) or '').strip()
            if not existing or existing in {'-', 'None'}:
                enhanced_row[target_field] = resolved_ports
    
    return enhanced_row

def infer_protocol_port_from_record(record: dict) -> dict:
    enhanced = {}
    for key, value in record.items():
        if not isinstance(value, str):
            continue
        val = value.strip()
        if not val:
            continue
        parsed = parse_service_field(val)
        proto = parsed.get('protocol')
        port = parsed.get('port')
        if port:
            if 'dest_port' not in enhanced:
                enhanced['dest_port'] = port
        if proto and proto.upper() in ['TCP','UDP','ICMP','IP']:
            if 'protocol' not in enhanced:
                enhanced['protocol'] = proto
        if 'protocol' in enhanced and 'dest_port' in enhanced:
            break
    return enhanced

def resolve_protocol_port_from_mixed_field(field_value: str) -> dict:
    import re
    raw = str(field_value or '')
    # Split on common separators ; , and whitespace
    tokens = [t.strip() for t in re.split(r'[;,]|\s+', raw) if t.strip()]
    ports = []
    protos = []
    valid_protocols = {'TCP','UDP','ICMP','IP'}
    skip_tokens = {'-', 'NONE', 'ANY', 'ALLOW'}
    for tok in tokens:
        up = tok.upper()
        if up in skip_tokens:
            continue
        # Normalize patterns like "53 UDP" -> "53/UDP"
        m = re.match(r'^(\d+)\s+([A-Z]+)$', up)
        if m:
            tok = f"{m.group(1)}/{m.group(2)}"
        parsed = parse_service_field(tok)
        port = parsed.get('port')
        proto = parsed.get('protocol')
        if port:
            ports.append(str(port))
        if proto and proto.upper() in valid_protocols:
            protos.append(proto.upper())
    # Deduplicate ports preserving first-seen order
    seen = set()
    unique_ports_list = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            unique_ports_list.append(p)
    unique_ports = ';'.join(unique_ports_list) if unique_ports_list else None
    proto_set = set(protos)
    protocol = list(proto_set)[0] if len(proto_set) == 1 else None
    return {'protocol': protocol, 'dest_port': unique_ports}


# Test function for development
if __name__ == "__main__":
    # Test cases
    test_cases = [
        "TCP/80",
        "UDP/53", 
        "ICMP/0",
        "tcp/443",
        "80/TCP",
        "53/UDP",
        "TCP:22",
        "HTTP",
        "HTTPS",
        "SSH",
        "DNS",
        "PING",
        "443",
        "TCP",
        "invalid/format/test"
    ]
    
    print("Testing enhanced protocol/port parser with service mapping API:")
    print("=" * 80)
    
    for test in test_cases:
        service_info = parse_service_field(test)
        protocol_str = service_info.get('protocol') or "None"
        port_str = service_info.get('port') or "None"
        service_name = service_info.get('service_name') or 'None'

        print(f"{test:20} -> Protocol: {protocol_str:8} Port: {port_str:8} Service: {service_name}")
    
    print("\n" + "=" * 80)
    print("Testing multi-service parsing:")
    
    multi_service_tests = [
        "TCP-80;UDP-53",
        "HTTPS;SSH;FTP",
        "TCP/443;UDP/161;TCP/22"
    ]
    
    for test in multi_service_tests:
        print(f"\nInput: {test}")
        ports_info = parse_ports_with_services(test)
        for i, port_info in enumerate(ports_info, 1):
            print(f"  Port {i}: {port_info['display']} (Service: {port_info['service_name'] or 'Unknown'})")
    
    print("\n" + "=" * 80)
    print("Testing individual port lookups:")
    
    port_tests = [80, 443, 22, 53, 3389, 9999]
    for port_num in port_tests:
        port_info = get_port_with_service_info(str(port_num), 'tcp')
        print(f"Port {port_num}: {port_info['display']}")