"""
Intelligent Field Detection Service
Automatically detects and suggests field mappings for uploaded files
"""
import pandas as pd
import re
import json
from typing import Dict, List, Any, Optional, Tuple
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class FieldDetectionService:
    """Service for intelligent field detection and mapping suggestions"""
    
    def __init__(self):
        self.field_patterns = self._initialize_field_patterns()
        self.common_variations = self._initialize_common_variations()
        self.mandatory_fields = self._initialize_mandatory_fields()
        self.important_fields = self._initialize_important_fields()
        
    def _initialize_field_patterns(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize regex patterns for different field types"""
        return {
            'firewall': {
                'source': [
                    r'source.*ip', r'src.*ip', r'from.*ip', r'origin.*ip',
                    r'source.*addr', r'src.*addr', r'from.*addr',
                    r'^source$', r'^src$', r'^from$', r'client.*ip', r'internal.*ip'
                ],
                'source_zone': [
                    r'source.*zone', r'src.*zone', r'from.*zone', r'^source\s+zone$', r'^src\s+zone$', r'^from\s+zone$'
                ],
                'destination': [
                    r'dest.*ip', r'dst.*ip', r'to.*ip', r'target.*ip',
                    r'dest.*addr', r'dst.*addr', r'to.*addr',
                    r'^destination$', r'^dest$', r'^dst$', r'^to$', r'server.*ip', r'external.*ip'
                ],
                'dest_zone': [
                    r'dest.*zone', r'dst.*zone', r'to.*zone', r'target.*zone', r'^destination\s+zone$', r'^dest\s+zone$', r'^dst\s+zone$', r'^to\s+zone$'
                ],
                'source_port': [
                    r'source.*port', r'src.*port', r'from.*port', r'origin.*port',
                    r'^src\s+port$', r'^source\s+port$', r'sport', r'client.*port', r'internal.*port'
                ],
                'dest_port': [
                    r'dest.*port', r'dst.*port', r'to.*port', r'target.*port',
                    r'^dst\s+port$', r'^dest\s+port$', r'^destination\s+port$',
                    r'dport', r'server.*port', r'external.*port', r'port'
                ],
                'protocol': [
                    r'protocol', r'^proto$', r'service.*type', r'ip.*proto',
                    r'transport'
                ],
                'action': [
                    r'action', r'permit', r'deny', r'allow', r'block', r'rule.*action',
                    r'verdict', r'^decision$', r'result', r'status'
                ],
                'service': [
                    r'service', r'^svc$', r'app.*service', r'application.*service',
                    r'^app$', r'application'
                ],
                'application': [
                    r'^application$', r'^app$', r'application.*name', r'app.*name', r'client.*application', r'server.*application'
                ],
                'rule_name': [
                    r'^rule.*name$', r'^rule\s+name$', r'^name.*rule$', r'rule.*id',
                    r'rule.*identifier', r'policy.*name', r'^name$', r'^Name$'
                ],
                'acl_name': [
                    r'^acl.*name$', r'^acl$', r'access.*list.*name', r'access.*control.*list'
                ],
                'rule_text': [
                    r'rule.*text', r'raw.*rule', r'config.*line', r'rule.*line',
                    r'command', r'configuration', r'rule', r'text', r'raw',
                    r'observation', r'finding', r'entry'
                ],
                'line_number': [
                    r'line.*num', r'line.*no', r'seq.*num', r'sequence', r'order',
                    r'index', r'id', r'number', r'#', r'^line$'
                ],
                'rule_type': [
                    r'rule.*type', r'acl.*type', r'policy.*type', r'^type$',
                    r'category', r'class', r'kind'
                ],
                'hit_count': [
                    r'hit.*count', r'hits', r'count', r'usage.*count', r'match.*count',
                    r'frequency', r'occurrences', r'matches', r'times.*used',
                    r'activity.*count', r'traffic.*count', r'access.*count'
                ]
            },
            'cmdb': {
                'hostname': [
                    r'hostname', r'host.*name', r'server.*name', r'device.*name',
                    r'computer.*name', r'machine.*name'
                ],
                'ip_address': [
                    r'ip.*addr', r'ip.*address', r'ipv4', r'ip'
                ],
                'application': [
                    r'application', r'app', r'service', r'application.*name', r'app.*name', r'service.*name'
                ],
                'application_name': [
                    r'application', r'app.*name', r'application.*name', r'service.*name'
                ],
                'asset_type': [
                    r'asset.*type', r'device.*type', r'type', r'category',
                    r'classification'
                ],
                'environment': [
                    r'environment', r'env', r'stage', r'tier', r'zone'
                ],
                'owner': [
                    r'owner', r'responsible', r'contact', r'admin', r'manager',
                    r'custodian', r'point.*of.*contact', r'primary.*contact', r'po\b', r'owned\s*by'
                ],
                'location': [
                    r'location', r'site', r'datacenter', r'dc', r'facility',
                    r'building', r'room'
                ],
                'description': [
                    r'description', r'desc', r'comment', r'notes', r'details'
                ],
                'department': [
                    r'department', r'dept', r'division', r'team', r'group'
                ]
                ,
                'pcidss_asset_category': [
                    r'pci.*dss.*category', r'pci.*category', r'pcidss.*asset.*category', r'cardholder.*data.*category',
                    r'^pci$', r'^pcidss$', r'^category$'
                ],
                'asset_tag': [
                    r'asset.*tag', r'tag', r'asset.*id', r'asset.*identifier', r'serial.*number', r'serial.*id'
                ],
                'business_unit': [
                    r'business.*unit', r'bu', r'division', r'business.*division', r'organizational.*unit'
                ],
                'cost_center': [
                    r'cost.*center', r'cc', r'cost.*code', r'budget.*code', r'accounting.*code'
                ],
                'mac_address': [
                    r'mac.*address', r'mac', r'physical.*address', r'hardware.*address', r'ethernet.*address'
                ],
                'manufacturer': [
                    r'manufacturer', r'vendor', r'maker', r'brand', r'company', r'producer'
                ],
                'model': [
                    r'model', r'model.*number', r'product.*model', r'device.*model', r'part.*number'
                ],
                'operating_system': [
                    r'operating.*system', r'os', r'platform', r'system.*software', r'os.*name'
                ],
                'serial_number': [
                    r'serial.*number', r'serial', r'sn', r'serial.*id', r'asset.*serial'
                ],
                'status': [
                    r'status', r'state', r'condition', r'health', r'availability', r'operational.*status'
                ]
            },
            'vlan': {
                'location': [
                    r'location', r'site', r'datacenter', r'dc', r'building', r'floor'
                ],
                'subnet': [
                    r'subnet', r'network', r'cidr', r'ip.*range', r'address.*range'
                ],
                'description': [
                    r'description', r'desc', r'comment', r'notes', r'purpose'
                ]
            }
            ,
            'objects': {
                'name': [
                    r'^name$', r'object.*name', r'group.*name', r'alias', r'label'
                ],
                'type': [
                    r'^type$', r'object.*type', r'member.*type', r'category'
                ],
                'ip_address': [
                    r'ip.*addr', r'ip.*address', r'^ip$', r'address', r'ipv4', r'subnet', r'cidr'
                ],
                'interface': [
                    r'^interface$', r'iface', r'intf', r'nic'
                ],
                'details': [
                    r'^details$', r'description', r'notes', r'comment'
                ]
            }
        }
    
    def _initialize_common_variations(self) -> Dict[str, List[str]]:
        """Initialize common column name variations"""
        return {
            'separators': ['_', '-', '.', ' '],
            'prefixes': ['src', 'dst', 'source', 'dest', 'destination', 'from', 'to'],
            'suffixes': ['addr', 'address', 'ip', 'port', 'num', 'number', 'id']
        }
    
    def _initialize_mandatory_fields(self) -> Dict[str, List[str]]:
        """Initialize mandatory fields for each file type"""
        return {
            'firewall': ['source', 'destination', 'dest_port'],
            'cmdb': ['hostname', 'ip_address'],
            'vlan': ['subnet'],
            'objects': ['name']
        }
    
    def _initialize_important_fields(self) -> Dict[str, List[str]]:
        """Initialize important (but not mandatory) fields for each file type"""
        return {
            'firewall': ['action', 'protocol', 'source_port', 'hit_count', 'rule_status', 'line_number'],
            'cmdb': ['asset_type', 'location', 'owner', 'pcidss_asset_category', 'application_name', 'application', 'asset_tag', 'business_unit', 'cost_center', 'mac_address', 'manufacturer', 'model', 'operating_system', 'serial_number', 'status'],
            'vlan': ['description', 'location'],
            'objects': ['type', 'ip_address', 'details', 'interface']
        }
    
    def _get_field_priority(self, field_name: str, file_type: str) -> str:
        """Get the priority level of a field (mandatory, important, optional)"""
        mandatory_fields = self.mandatory_fields.get(file_type, [])
        important_fields = self.important_fields.get(file_type, [])
        
        if field_name in mandatory_fields:
            return 'mandatory'
        elif field_name in important_fields:
            return 'important'
        else:
            return 'optional'
    
    def analyze_file(self, file_path: str, file_type: str, max_rows: int = 100) -> Dict[str, Any]:
        """
        Analyze a file and return field detection results
        
        Args:
            file_path: Path to the file to analyze
            file_type: Type of file ('firewall', 'cmdb', 'vlan')
            max_rows: Maximum number of rows to analyze for performance
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            logger.info(f"Analyzing file: {file_path}, type: {file_type}")
            
            # Read file based on extension
            file_extension = Path(file_path).suffix.lower()
            logger.info(f"File extension: {file_extension}")
            
            if file_extension == '.csv':
                df = pd.read_csv(file_path, nrows=max_rows)
            elif file_extension in ['.xlsx', '.xls']:
                xls = pd.ExcelFile(file_path)
                frames = []
                for sheet in xls.sheet_names:
                    try:
                        frames.append(pd.read_excel(file_path, sheet_name=sheet, nrows=max_rows))
                    except Exception:
                        continue
                if not frames:
                    raise ValueError("No readable sheets found in Excel file")
                df = pd.concat(frames, ignore_index=True)
            elif file_extension == '.json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        df = pd.DataFrame(data[:max_rows])
                    else:
                        raise ValueError("JSON file must contain an array of objects")
            elif file_extension in ['.txt', '.conf']:
                # For text files, try to detect structure
                return self._analyze_text_file(file_path, file_type)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
            
            # Analyze structured data (CSV, Excel, JSON)
            result = self._analyze_structured_data(df, file_type)
            logger.info(f"Analysis result - detected_fields count: {len(result.get('detected_fields', {}))}")
            logger.info(f"Analysis result - columns: {result.get('columns', [])}")
            logger.info(f"Analysis result - confidence_scores: {result.get('confidence_scores', {})}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'detected_fields': {},
                'suggestions': {},
                'preview_data': [],
                'confidence_scores': {}
            }
    
    def _analyze_structured_data(self, df: pd.DataFrame, file_type: str) -> Dict[str, Any]:
        """Analyze structured data (CSV, Excel, JSON)"""
        columns = df.columns.tolist()
        preview_data = df.head(5).to_dict('records')
        
        logger.info(f"Analyzing structured data - columns: {columns}")
        
        # Detect field mappings
        detected_fields = {}
        suggestions = {}
        confidence_scores = {}
        
        for column in columns:
            logger.info(f"Processing column: {column}")
            field_match, confidence = self._detect_field_type(column, df[column], file_type)
            logger.info(f"Column '{column}' -> field: {field_match}, confidence: {confidence}")
            
            if field_match:
                detected_fields[column] = field_match
                confidence_scores[column] = confidence
                
                # Generate alternative suggestions
                alternatives = self._get_alternative_suggestions(column, df[column], file_type)
                if alternatives:
                    suggestions[column] = alternatives
        
        logger.info(f"Final detected_fields: {detected_fields}")
        logger.info(f"Final confidence_scores: {confidence_scores}")
        
        # Add field priorities and validation
        field_priorities = {}
        mandatory_missing = []
        important_missing = []
        
        # Check which mandatory and important fields are detected
        mandatory_fields = self.mandatory_fields.get(file_type, [])
        important_fields = self.important_fields.get(file_type, [])
        
        detected_field_values = list(detected_fields.values())
        
        for field in mandatory_fields:
            if field not in detected_field_values:
                mandatory_missing.append(field)
        
        for field in important_fields:
            if field not in detected_field_values:
                important_missing.append(field)
        
        # Add priority information for detected fields
        for column, field in detected_fields.items():
            field_priorities[column] = self._get_field_priority(field, file_type)
        
        # Clean confidence scores to ensure no NaN or invalid values
        cleaned_confidence_scores = {}
        for key, value in confidence_scores.items():
            if pd.isna(value) or not isinstance(value, (int, float)):
                cleaned_confidence_scores[key] = 0.0
            else:
                cleaned_confidence_scores[key] = round(float(value), 2)
        
        return {
            'success': True,
            'detected_fields': detected_fields,
            'suggestions': suggestions,
            'preview_data': preview_data,
            'confidence_scores': cleaned_confidence_scores,
            'field_priorities': field_priorities,
            'mandatory_missing': mandatory_missing,
            'important_missing': important_missing,
            'columns': columns,
            'total_rows': len(df),
            'file_type': file_type
        }
    
    def _analyze_text_file(self, file_path: str, file_type: str) -> Dict[str, Any]:
        """Analyze text configuration files"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:100]  # Read first 100 lines
            
            # Detect file format patterns
            format_info = self._detect_text_format(lines)
            
            return {
                'success': True,
                'detected_fields': {},
                'suggestions': {},
                'preview_data': lines[:10],  # Show first 10 lines as preview
                'confidence_scores': {},
                'format_info': format_info,
                'total_lines': len(lines),
                'file_type': file_type,
                'is_text_config': True
            }
            
        except Exception as e:
            logger.error(f"Error analyzing text file {file_path}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'detected_fields': {},
                'suggestions': {},
                'preview_data': [],
                'confidence_scores': {}
            }
    
    def _detect_field_type(self, column_name: str, column_data: pd.Series, file_type: str) -> Tuple[Optional[str], float]:
        """
        Detect the most likely field type for a column
        
        Returns:
            Tuple of (field_name, confidence_score)
        """
        if file_type not in self.field_patterns:
            return None, 0.0
        
        patterns = self.field_patterns[file_type]
        best_match = None
        best_score = 0.0
        
        # Normalize column name for matching
        normalized_column = column_name.lower().strip()
        
        for field_name, field_patterns in patterns.items():
            score = self._calculate_field_score(normalized_column, column_data, field_patterns)
            if score > best_score:
                best_score = score
                best_match = field_name
        
        # Only return matches with reasonable confidence
        if best_score >= 0.1:  # Lowered threshold from 0.2 to 0.1
            return best_match, best_score
        
        return None, 0.0
    
    def _calculate_field_score(self, column_name: str, column_data: pd.Series, patterns: List[str]) -> float:
        """Calculate confidence score for field matching"""
        score = 0.0
        
        # Score based on column name matching
        for pattern in patterns:
            if re.search(pattern, column_name, re.IGNORECASE):
                score += 0.7
                break
        
        # Score based on data content analysis
        content_score = self._analyze_column_content(column_data, patterns)
        score += content_score * 0.3
        
        # For IP address fields, require at least some IP-looking values; otherwise reject
        try:
            if any('ip' in pattern for pattern in patterns):
                sample_values = column_data.dropna().head(10).astype(str)
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ip_matches = sum(1 for val in sample_values if re.search(ip_pattern, val))
                if ip_matches == 0:
                    return 0.0
        except Exception:
            pass

        # Round to 2 decimal places and ensure it's not NaN
        final_score = min(score, 1.0)
        if pd.isna(final_score) or not isinstance(final_score, (int, float)):
            final_score = 0.0
        return round(final_score, 2)
    
    def _analyze_column_content(self, column_data: pd.Series, patterns: List[str]) -> float:
        """Analyze column content to determine field type likelihood"""
        if column_data.empty:
            return 0.0
        
        # Sample some non-null values
        sample_values = column_data.dropna().head(10).astype(str)
        if sample_values.empty:
            return 0.0
        
        # Check for IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_matches = sum(1 for val in sample_values if re.search(ip_pattern, val))
        if ip_matches > len(sample_values) * 0.5:
            if any('ip' in pattern for pattern in patterns):
                return 0.8
        
        # Check for port numbers
        port_pattern = r'\b(?:[1-9][0-9]{0,4})\b'
        port_matches = 0
        for val in sample_values:
            if re.match(port_pattern, val):
                try:
                    port_num = int(val)
                    if port_num <= 65535:
                        port_matches += 1
                except ValueError:
                    # Skip values that can't be converted to int (e.g., "172.16.142.159;Imac_New_Servers")
                    continue
        if port_matches > len(sample_values) * 0.5:
            if any('port' in pattern for pattern in patterns):
                return 0.8
        
        # Check for protocol names
        protocols = ['tcp', 'udp', 'icmp', 'ip', 'http', 'https', 'ssh', 'ftp']
        protocol_matches = sum(1 for val in sample_values if val.lower() in protocols)
        if protocol_matches > len(sample_values) * 0.3:
            if any('protocol' in pattern for pattern in patterns):
                return 0.7
        
        # Check for action keywords
        actions = ['permit', 'deny', 'allow', 'block', 'accept', 'drop']
        action_matches = sum(1 for val in sample_values if val.lower() in actions)
        if action_matches > len(sample_values) * 0.3:
            if any('action' in pattern for pattern in patterns):
                return 0.7
        
        return 0.2  # Default low score for content analysis
    
    def _get_alternative_suggestions(self, column_name: str, column_data: pd.Series, file_type: str) -> List[Dict[str, Any]]:
        """Get alternative field suggestions with confidence scores"""
        if file_type not in self.field_patterns:
            return []
        
        patterns = self.field_patterns[file_type]
        suggestions = []
        
        normalized_column = column_name.lower().strip()
        
        for field_name, field_patterns in patterns.items():
            score = self._calculate_field_score(normalized_column, column_data, field_patterns)
            if score >= 0.2:  # Lower threshold for alternatives
                suggestions.append({
                    'field': field_name,
                    'confidence': score,
                    'reason': self._get_match_reason(normalized_column, column_data, field_patterns)
                })
        
        # Sort by confidence score
        suggestions.sort(key=lambda x: x['confidence'], reverse=True)
        return suggestions[:3]  # Return top 3 suggestions
    
    def _get_match_reason(self, column_name: str, column_data: pd.Series, patterns: List[str]) -> str:
        """Get human-readable reason for field match"""
        reasons = []
        
        # Check name matching
        for pattern in patterns:
            if re.search(pattern, column_name, re.IGNORECASE):
                reasons.append(f"Column name matches pattern '{pattern}'")
                break
        
        # Check content patterns
        if not column_data.empty:
            sample_values = column_data.dropna().head(5).astype(str)
            if len(sample_values) > 0:
                reasons.append(f"Sample values: {', '.join(sample_values.tolist()[:3])}")
        
        return '; '.join(reasons) if reasons else "Pattern match"
    
    def _detect_text_format(self, lines: List[str]) -> Dict[str, Any]:
        """Detect format information for text configuration files"""
        format_info = {
            'likely_vendor': 'unknown',
            'has_access_lists': False,
            'has_object_groups': False,
            'has_nat_rules': False,
            'line_format': 'unknown'
        }
        
        # Check for Cisco ASA patterns
        cisco_patterns = [
            r'access-list\s+\w+',
            r'object-group\s+\w+',
            r'nat\s+\(',
            r'hostname\s+\w+'
        ]
        
        cisco_matches = 0
        for line in lines:
            for pattern in cisco_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    cisco_matches += 1
                    break
        
        if cisco_matches > len(lines) * 0.1:
            format_info['likely_vendor'] = 'cisco_asa'
        
        # Check for specific rule types
        for line in lines:
            if re.search(r'access-list', line, re.IGNORECASE):
                format_info['has_access_lists'] = True
            if re.search(r'object-group', line, re.IGNORECASE):
                format_info['has_object_groups'] = True
            if re.search(r'nat\s+\(', line, re.IGNORECASE):
                format_info['has_nat_rules'] = True
        
        return format_info
    
    def get_available_fields(self, file_type: str) -> List[Dict[str, str]]:
        """Get list of available fields for a given file type"""
        if file_type not in self.field_patterns:
            return []
        
        mandatory_fields = self.mandatory_fields.get(file_type, [])
        important_fields = self.important_fields.get(file_type, [])
        fields = []
        
        # Sort fields by priority: mandatory first, then important, then optional
        all_fields = list(self.field_patterns[file_type].keys())
        sorted_fields = []
        
        # Add mandatory fields first
        for field in mandatory_fields:
            if field in all_fields:
                sorted_fields.append(field)
        
        # Add important fields second
        for field in important_fields:
            if field in all_fields and field not in sorted_fields:
                sorted_fields.append(field)
        
        # Add remaining optional fields
        for field in all_fields:
            if field not in sorted_fields:
                sorted_fields.append(field)
        
        for field_name in sorted_fields:
            priority = self._get_field_priority(field_name, file_type)
            fields.append({
                'value': field_name,
                'label': field_name.replace('_', ' ').title(),
                'description': self._get_field_description(field_name, file_type),
                'mandatory': field_name in mandatory_fields,
                'important': field_name in important_fields,
                'priority': priority
            })
        
        return fields
    
    def _get_field_description(self, field_name: str, file_type: str) -> str:
        """Get description for a field"""
        descriptions = {
            'firewall': {
                'source': 'Source IP address or network',
                'destination': 'Destination IP address or network',
                'source_port': 'Source port number or range',
                'dest_port': 'Destination port number or range',
                'protocol': 'Network protocol (TCP, UDP, ICMP, etc.)',
                'action': 'Rule action (permit, deny, allow, block)',
                'source_zone': 'Source zone name from policy',
                'dest_zone': 'Destination zone name from policy',
                'application': 'Application name for the rule',
                'rule_name': 'Name or identifier of the firewall rule',
                'rule_text': 'Raw rule configuration text',
                'line_number': 'Line number in configuration',
                'rule_type': 'Type of firewall rule'
            },
            'cmdb': {
                'hostname': 'Device hostname or computer name',
                'ip_address': 'IP address of the device',
                'asset_type': 'Type of asset (server, workstation, etc.)',
                'environment': 'Environment (prod, dev, test, etc.)',
                'owner': 'Asset owner or responsible person',
                'location': 'Physical location or datacenter',
                'description': 'Asset description or notes',
                'department': 'Department or team owning the asset',
                'pcidss_asset_category': 'PCI DSS asset category: A (Cardholder data), B (Supporting services), C (No cardholder data)',
                'application': 'Application name or service',
                'application_name': 'Application name or service',
                'asset_tag': 'Asset tag or serial identifier',
                'business_unit': 'Business unit or organizational division',
                'cost_center': 'Cost center or budget code',
                'mac_address': 'MAC address or hardware address',
                'manufacturer': 'Device manufacturer or vendor',
                'model': 'Device model or product name',
                'operating_system': 'Operating system name and version',
                'serial_number': 'Serial number or hardware identifier',
                'status': 'Asset status (active, inactive, decommissioned, etc.)'
            },
            'vlan': {
                'location': 'Physical location or datacenter for the VLAN',
                'subnet': 'Network subnet or CIDR',
                'description': 'VLAN description or purpose'
            },
            'objects': {
                'name': 'Object or group name',
                'type': 'Object member type (host, subnet, range, service)',
                'ip_address': 'IP address, subnet, CIDR, or range',
                'interface': 'Interface or context indicator',
                'details': 'Details or description for the object'
            }
        }
        
        return descriptions.get(file_type, {}).get(field_name, 'Field description')
    
    def analyze_dataframe_columns(self, df: pd.DataFrame, file_type: str) -> Dict[str, Any]:
        """
        Analyze DataFrame columns to detect field mappings
        
        Args:
            df: DataFrame to analyze
            file_type: Type of file (firewall, cmdb, vlan)
            
        Returns:
            Analysis result with detected field mappings
        """
        try:
            return self._analyze_structured_data(df, file_type)
        except Exception as e:
            logger.error(f"Error analyzing DataFrame columns: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'detected_fields': {},
                'suggestions': {},
                'preview_data': [],
                'confidence_scores': {}
            }


# Global service instance
field_detection_service = FieldDetectionService()