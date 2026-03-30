import pandas as pd
import json
import re
from typing import List, Dict, Any
from models import RawFirewallRule, CMDBAsset, VLANNetwork, ObjectGroup, ObjectGroupMember

class FirewallConfigParser:
    """Parser for various firewall configuration formats"""
    
    def __init__(self):
        self.supported_formats = ['.txt', '.conf', '.csv', '.xlsx', '.json']
    
    def parse_file(self, file_path: str, file_type: str) -> List[Dict[str, Any]]:
        """Parse firewall configuration file based on type"""
        if file_type.lower() == 'csv':
            return self._parse_csv(file_path)
        elif file_type.lower() in ['xlsx', 'xls']:
            return self._parse_excel(file_path)
        elif file_type.lower() == 'json':
            return self._parse_json(file_path)
        elif file_type.lower() in ['txt', 'conf']:
            return self._parse_text_config(file_path)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    def _parse_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse CSV firewall rules"""
        df = pd.read_csv(file_path)
        rules = []
        
        # Define column mapping variations
        column_mappings = {
            'source_ip': ['source_ip', 'Source IP', 'source', 'Source', 'src_ip', 'Src IP'],
            'destination_ip': ['destination_ip', 'Destination IP', 'destination', 'Destination', 'dest_ip', 'Dest IP'],
            'source_port': ['source_port', 'Source Port', 'src_port', 'Src Port'],
            'dest_port': ['dest_port', 'destination_port', 'Destination Port', 'Port', 'port'],
            'protocol': ['protocol', 'Protocol', 'proto', 'Proto'],
            'action': ['action', 'Action', 'rule_type', 'Rule Type', 'decision', 'Decision'],
            'rule_text': ['rule_text', 'Rule Text', 'raw_text', 'Raw Text', 'text', 'Text']
        }
        
        def get_column_value(row, field_name):
            """Get value from row using flexible column mapping"""
            for possible_col in column_mappings.get(field_name, [field_name]):
                if possible_col in row.index:
                    return str(row.get(possible_col, '')).strip()
            return ''
        
        for index, row in df.iterrows():
            rule = {
                'line_number': index + 1,
                'rule_text': get_column_value(row, 'rule_text') or str(row.to_dict()),
                'source_ip': get_column_value(row, 'source_ip'),
                'destination_ip': get_column_value(row, 'destination_ip'),
                'source_port': get_column_value(row, 'source_port'),
                'dest_port': get_column_value(row, 'dest_port'),
                'protocol': get_column_value(row, 'protocol'),
                'rule_type': get_column_value(row, 'action') or 'permit'
            }
            rules.append(rule)
        return rules
    
    def _parse_excel(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Excel firewall rules"""
        df = pd.read_excel(file_path)
        rules = []
        
        # Define column mapping variations
        column_mappings = {
            'source_ip': ['source_ip', 'Source IP', 'source', 'Source', 'src_ip', 'Src IP'],
            'destination_ip': ['destination_ip', 'Destination IP', 'destination', 'Destination', 'dest_ip', 'Dest IP'],
            'source_port': ['source_port', 'Source Port', 'src_port', 'Src Port'],
            'dest_port': ['dest_port', 'destination_port', 'Destination Port', 'Port', 'port'],
            'protocol': ['protocol', 'Protocol', 'proto', 'Proto'],
            'action': ['action', 'Action', 'rule_type', 'Rule Type', 'decision', 'Decision'],
            'rule_text': ['rule_text', 'Rule Text', 'raw_text', 'Raw Text', 'text', 'Text']
        }
        
        def get_column_value(row, field_name):
            """Get value from row using flexible column mapping"""
            for possible_col in column_mappings.get(field_name, [field_name]):
                if possible_col in row.index:
                    return str(row.get(possible_col, '')).strip()
            return ''
        
        for index, row in df.iterrows():
            rule = {
                'line_number': index + 1,
                'rule_text': get_column_value(row, 'rule_text') or str(row.to_dict()),
                'source_ip': get_column_value(row, 'source_ip'),
                'destination_ip': get_column_value(row, 'destination_ip'),
                'source_port': get_column_value(row, 'source_port'),
                'dest_port': get_column_value(row, 'dest_port'),
                'protocol': get_column_value(row, 'protocol'),
                'rule_type': get_column_value(row, 'action') or 'permit'
            }
            rules.append(rule)
        return rules
    
    def _parse_json(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse JSON firewall configuration"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        rules = []
        if isinstance(data, list):
            for i, rule in enumerate(data):
                parsed_rule = {
                    'line_number': i + 1,
                    'rule_text': json.dumps(rule),
                    'source_ip': rule.get('source', ''),
                    'destination_ip': rule.get('destination', ''),
                    'port': rule.get('port', ''),
                    'protocol': rule.get('protocol', ''),
                    'rule_type': rule.get('action', 'permit')
                }
                rules.append(parsed_rule)
        return rules
    
    def _parse_text_config(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse text-based firewall configuration files"""
        rules = []
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Basic ACL parsing patterns
            acl_patterns = [
                r'access-list\s+\w+\s+(permit|deny)\s+(\w+)\s+(\S+)\s+(\S+)(?:\s+eq\s+(\w+))?',
                r'(permit|deny)\s+(\w+)\s+(\S+)\s+(\S+)(?:\s+eq\s+(\w+))?'
            ]
            
            rule = {
                'line_number': line_num,
                'rule_text': line,
                'source_ip': '',
                'destination_ip': '',
                'port': '',
                'protocol': '',
                'rule_type': ''
            }
            
            for pattern in acl_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    groups = match.groups()
                    rule['rule_type'] = groups[0]
                    rule['protocol'] = groups[1] if len(groups) > 1 else ''
                    rule['source_ip'] = groups[2] if len(groups) > 2 else ''
                    rule['destination_ip'] = groups[3] if len(groups) > 3 else ''
                    rule['port'] = groups[4] if len(groups) > 4 and groups[4] else ''
                    break
            
            rules.append(rule)
        
        return rules

class CMDBParser:
    """Parser for CMDB data"""
    
    def parse_cmdb_file(self, file_path: str, file_type: str) -> List[Dict[str, Any]]:
        """Parse CMDB inventory file"""
        if file_type.lower() == 'csv':
            return self._parse_cmdb_csv(file_path)
        elif file_type.lower() in ['xlsx', 'xls']:
            return self._parse_cmdb_excel(file_path)
        else:
            raise ValueError(f"Unsupported CMDB file type: {file_type}")
    
    def _parse_cmdb_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse CSV CMDB data"""
        df = pd.read_csv(file_path)
        assets = []
        for _, row in df.iterrows():
            asset = {
                'ip_address': row.get('IP Address', row.get('ip_address', '')),
                'hostname': row.get('Hostname', row.get('hostname', '')),
                'owner': row.get('Owner', row.get('owner', '')),
                'department': row.get('Department', row.get('department', '')),
                'asset_type': row.get('Asset Type', row.get('asset_type', '')),
                'operating_system': row.get('OS', row.get('os', '')),
                'location': row.get('Location', row.get('location', '')),
                'environment': row.get('Environment', row.get('environment', '')),
                'status': row.get('Status', row.get('status', 'active'))
            }
            assets.append(asset)
        return assets
    
    def _parse_cmdb_excel(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Excel CMDB data"""
        df = pd.read_excel(file_path)
        assets = []
        for _, row in df.iterrows():
            asset = {
                'ip_address': row.get('ip_address', ''),
                'hostname': row.get('hostname', ''),
                'owner': row.get('owner', ''),
                'department': row.get('department', ''),
                'asset_type': row.get('asset_type', ''),
                'operating_system': row.get('os', ''),
                'location': row.get('location', ''),
                'status': row.get('status', 'active')
            }
            assets.append(asset)
        return assets

class VLANParser:
    """Parser for VLAN network data"""
    
    def parse_vlan_file(self, file_path: str, file_type: str) -> List[Dict[str, Any]]:
        """Parse VLAN network file"""
        if file_type.lower() == 'csv':
            return self._parse_vlan_csv(file_path)
        elif file_type.lower() in ['xlsx', 'xls']:
            return self._parse_vlan_excel(file_path)
        else:
            raise ValueError(f"Unsupported VLAN file type: {file_type}")
    
    def _parse_vlan_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse CSV VLAN data"""
        df = pd.read_csv(file_path)
        vlans = []
        for _, row in df.iterrows():
            vlan = {
                'vlan_id': int(row.get('VLAN ID', row.get('vlan_id', 0))),
                'name': row.get('VLAN Name', row.get('name', '')),
                'subnet': row.get('Network', row.get('subnet', '')),
                'description': row.get('Description', row.get('description', '')),
                'gateway': row.get('gateway', ''),
                'environment': row.get('Environment', row.get('environment', ''))
            }
            vlans.append(vlan)
        return vlans
    
    def _parse_vlan_excel(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Excel VLAN data"""
        df = pd.read_excel(file_path)
        vlans = []
        for _, row in df.iterrows():
            vlan = {
                'vlan_id': int(row.get('vlan_id', 0)),
                'name': row.get('name', ''),
                'subnet': row.get('subnet', ''),
                'description': row.get('description', ''),
                'gateway': row.get('gateway', '')
            }
            vlans.append(vlan)
        return vlans