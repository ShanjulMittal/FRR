"""
CSV/Excel Parser - Handles CSV and Excel files with column mapping
"""
import pandas as pd
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser
from protocol_port_parser import enhance_row_with_protocol_port
from field_detection_service import field_detection_service


class CSVParser(BaseParser):
    """Parser for CSV and Excel files with column mapping support"""
    
    def __init__(self, file_path: str, file_type: str, **kwargs):
        super().__init__(file_path, file_type, **kwargs)
        self.column_mapping = kwargs.get('column_mapping', {})
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.delimiter = kwargs.get('delimiter', ',')
    
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse CSV/Excel file and return structured data
        
        Returns:
            List of dictionaries containing parsed data
        """
        if not self.validate_file():
            raise ValueError(f"Invalid file: {self.file_path}")
        
        self.log_parsing_start()
        
        try:
            # Read the file based on extension
            if self.file_path.lower().endswith('.csv'):
                df = pd.read_csv(
                    self.file_path, 
                    encoding=self.encoding,
                    delimiter=self.delimiter
                )
            elif self.file_path.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(self.file_path)
            else:
                raise ValueError(f"Unsupported file format: {self.file_path}")
            
            # Preserve original DataFrame (headers and raw values) before any mapping/cleaning
            df_original = df.copy()
            
            # Apply column mapping if provided; when user mapping is present, do not override with intelligent mapping
            if self.column_mapping:
                df = self._apply_column_mapping(df)
            else:
                # Use intelligent field detection to automatically map columns
                df = self._apply_intelligent_mapping(df)
            
            # Preserve original row index for stitching back the raw row
            df['_original_row_index'] = df_original.index
            
            # Convert to list of dictionaries
            records = df.to_dict('records')
            
            # Clean and validate records
            cleaned_records = self._clean_records(records)
            
            # Attach original raw row per record using the preserved index
            original_records = df_original.to_dict('records')
            final_records = []
            for rec in cleaned_records:
                idx_val = rec.get('_original_row_index')
                try:
                    idx = int(idx_val) if idx_val is not None else None
                except Exception:
                    idx = None
                if idx is not None and 0 <= idx < len(original_records):
                    rec['original_row'] = original_records[idx]
                
                try:
                    mapped_fields = set()
                    try:
                        mf = rec.get('_mapped_fields') or []
                        mapped_fields = {str(x).strip().lower() for x in (mf if isinstance(mf, list) else [])}
                    except Exception:
                        mapped_fields = set()
                    allow_protocol = ('protocol' in mapped_fields) or ('service' in mapped_fields) or ('proto' in mapped_fields)
                    allow_dest_port = ('dest_port' in mapped_fields) or ('destination port' in mapped_fields) or ('service' in mapped_fields) or ('service_port' in mapped_fields) or ('port_protocol' in mapped_fields)
                    if not (allow_protocol or allow_dest_port):
                        final_records.append(rec)
                        continue
                    orig = rec.get('original_row') or {}
                    from protocol_port_parser import resolve_protocol_port_from_mixed_field
                    # Collect candidate service-like fields (strict header match)
                    candidate_values = []
                    allowed_keys = {
                        'service','svc','services','application',
                        'service_port','port','ports','dst port','dest port','destination port','protocol'
                    }
                    for k, v in (orig.items() if isinstance(orig, dict) else []):
                        if not isinstance(v, str) or not v.strip():
                            continue
                        kl = str(k).strip().lower()
                        kl_norm = kl.replace('_', ' ')
                        if kl_norm in allowed_keys:
                            candidate_values.append(v.strip())
                    # Resolve ports/protocols from combined candidate strings
                    merged_ports = []
                    chosen_protocol = None
                    seen = set()
                    for val in candidate_values:
                        resolved = resolve_protocol_port_from_mixed_field(val)
                        rp = str(resolved.get('dest_port') or '').strip()
                        if rp:
                            for p in [t.strip() for t in rp.split(';') if t.strip()]:
                                if p not in seen:
                                    seen.add(p)
                                    merged_ports.append(p)
                        proto = resolved.get('protocol')
                        if proto and not chosen_protocol:
                            chosen_protocol = proto
                    if allow_dest_port and merged_ports:
                        current = str(rec.get('dest_port') or '').strip()
                        if not current or current in {'-', 'None'}:
                            rec['dest_port'] = ';'.join(merged_ports)
                    # Override protocol when current is missing or invalid (only if mapped)
                    current_protocol = str(rec.get('protocol') or '').upper()
                    invalid_protocols = {'', 'ANY', 'ALLOW'}
                    if allow_protocol and (not current_protocol or current_protocol in invalid_protocols) and chosen_protocol:
                        rec['protocol'] = chosen_protocol
                except Exception:
                    pass
                final_records.append(rec)
            
            self.log_parsing_complete(len(final_records))
            return final_records
            
        except Exception as e:
            self.handle_parsing_error(e, "CSV/Excel parsing")
    
    def _apply_column_mapping(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply column mapping to create new columns with mapped field names
        while preserving original columns for data integrity
        
        Args:
            df: Original DataFrame
            
        Returns:
            DataFrame with additional mapped columns
        """
        # Create a copy of the original DataFrame
        df_mapped = df.copy()
        # Build case-insensitive header lookup
        def _norm(s: Any) -> str:
            try:
                return str(s).strip().lower()
            except Exception:
                return str(s)
        header_lookup = { _norm(col): col for col in df.columns }

        # Canonicalize target field names to internal schema
        def _canon_target(t: Any) -> str:
            raw = str(t or '').strip()
            if not raw:
                return raw
            l = raw.strip().lower()
            ln = l.replace('_', ' ').strip()
            # Objects imports: prefer object-oriented targets when selected
            if self.file_type == 'objects':
                if ln in {'name','object name','group name','alias','label'}: return 'name'
                if ln in {'type','object type','member type','category'}: return 'type'
                if ln in {'ip','ip address','ip addr','address','ipv4','subnet','cidr'}: return 'ip_address'
                if ln in {'interface','iface','intf','nic'}: return 'interface'
                if ln in {'details','description','notes','comment'}: return 'details'
            # Firewall/common rule fields
            if ln in {'rule name'}: return 'rule_name'
            if ln in {'protocol','proto'}: return 'protocol'
            if ln in {'source','src','source ip','src ip'}: return 'source'
            if ln in {'destination','dst','destination ip','dst ip'}: return 'destination'
            if ln in {'source port','src port'}: return 'source_port'
            if ln in {'destination port','dest port','dst port','port'}: return 'dest_port'
            if ln in {'source zone','src zone','from zone'}: return 'source_zone'
            if ln in {'destination zone','dest zone','dst zone','to zone'}: return 'dest_zone'
            if ln in {'application','app','app name','application name'}: return 'application'
            if ln in {'service'}: return 'service'
            if ln in {'service port','service_port'}: return 'service_port'
            if ln in {'port protocol','port_protocol'}: return 'port_protocol'
            # CMDB asset fields
            if ln in {'hostname','host name','host','asset name','device','node','server','vm name'}: return 'hostname'
            if ln in {'ip address','ip','ipaddr','address','ipv4'}: return 'ip_address'
            if ln in {'owner','application owner','asset owner','custodian'}: return 'owner'
            if ln in {'department','dept','business unit','bu'}: return 'department'
            if ln in {'environment','env','tier'}: return 'environment'
            if ln in {'location','site','datacenter','dc','building','floor'}: return 'location'
            if ln in {'asset type','category'}: return 'asset_type'
            if ln in {'type'}: return 'asset_type' if self.file_type == 'cmdb' else 'type'
            if ln in {'operating system','os'}: return 'operating_system'
            if ln in {'os version','version'}: return 'os_version'
            if ln in {'manufacturer','vendor'}: return 'manufacturer'
            if ln in {'model'}: return 'model'
            if ln in {'mac address','mac'}: return 'mac_address'
            if ln in {'serial number','serial'}: return 'serial_number'
            if ln in {'asset tag','tag','asset id'}: return 'asset_tag'
            if ln in {'business unit','bu'}: return 'business_unit'
            if ln in {'cost center'}: return 'cost_center'
            if ln in {'status'}: return 'status'
            if ln in {'description','desc','comment','notes','purpose'}: return 'description'
            if ln in {'application name','service name'}: return 'application_name'
            # Custom fields keep prefix but canonicalize base part
            if raw.startswith('custom_'):
                base = raw[7:]
                base_canon = _canon_target(base)
                return f"custom_{base_canon}" if base_canon else raw
            return raw
        
        # Build reverse mapping: target field -> list of original columns
        reverse_map: Dict[str, List[str]] = {}
        num_cols = len(df.columns)
        def _get_col_by_index(idx_raw: Any) -> Optional[str]:
            try:
                if isinstance(idx_raw, str) and idx_raw.strip().isdigit():
                    idx = int(idx_raw.strip())
                elif isinstance(idx_raw, int):
                    idx = idx_raw
                else:
                    return None
                if 0 <= idx < num_cols:
                    return df.columns[idx]
            except Exception:
                return None
            return None
        # Build reverse mapping per entry, supporting mixed orientations per pair
        for key, val in self.column_mapping.items():
            key_norm = _norm(key)
            key_in_headers = header_lookup.get(key_norm)
            # Prepare target fields list from val when key is original (header or numeric index)
            if key_in_headers is not None or (key_in_headers is None and _get_col_by_index(key) is not None):
                targets: List[str] = []
                if isinstance(val, list):
                    for mf in val:
                        if mf and str(mf).strip():
                            targets.append(_canon_target(mf))
                else:
                    if val and str(val).strip():
                        targets.append(_canon_target(val))
                source_col = key_in_headers if key_in_headers is not None else _get_col_by_index(key)
                for t in targets:
                    target = t[7:] if str(t).startswith('custom_') else str(t)
                    if source_col:
                        reverse_map.setdefault(target, []).append(source_col)
            else:
                # Treat key as target, value(s) as original source columns
                sources: List[str] = []
                if isinstance(val, list):
                    for oc in val:
                        actual_col = header_lookup.get(_norm(oc))
                        if not actual_col:
                            actual_col = _get_col_by_index(oc)
                        if actual_col:
                            sources.append(actual_col)
                else:
                    actual_col = header_lookup.get(_norm(val))
                    if not actual_col:
                        actual_col = _get_col_by_index(val)
                    if actual_col:
                        sources.append(actual_col)
                target = _canon_target(key)
                target = target[7:] if target.startswith('custom_') else target
                if sources:
                    reverse_map.setdefault(target, []).extend(sources)

        # Create or merge target columns from one or more source columns
        for target_field, source_cols in reverse_map.items():
            if len(source_cols) == 1:
                df_mapped[target_field] = df[source_cols[0]]
            else:
                # Concatenate non-empty values across multiple columns using comma separator
                df_mapped[target_field] = (
                    df[source_cols]
                        .astype(str)
                        .apply(lambda row: ', '.join([v.strip() for v in row if v and str(v).strip() and str(v).lower() != 'nan']), axis=1)
                )

        # Persist the list of mapped target fields for downstream visibility
        try:
            df_mapped['_mapped_fields'] = [list(reverse_map.keys())] * len(df_mapped)
            # Persist mapping sources dictionary for downstream enforcement
            df_mapped['_mapping_sources'] = [reverse_map] * len(df_mapped)
            df_mapped['_strict_mapping'] = [True] * len(df_mapped)
        except Exception:
            pass

        # Drop original columns that were mapped (to avoid duplication downstream)
        used_sources = set()
        for srcs in reverse_map.values():
            for s in srcs:
                used_sources.add(s)
        for col in used_sources:
            if col in df_mapped.columns:
                df_mapped = df_mapped.drop(columns=[col])
        
        self.logger.info(f"Applied column mapping: {self.column_mapping}")
        return df_mapped
    
    def _apply_intelligent_mapping(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply intelligent field detection to automatically map columns
        
        Args:
            df: DataFrame with original column names
            
        Returns:
            DataFrame with mapped column names
        """
        try:
            analysis_result = field_detection_service.analyze_dataframe_columns(df, self.file_type)
            if analysis_result.get('success') and analysis_result.get('detected_fields'):
                detected_mapping = analysis_result['detected_fields']
                rename_mapping: Dict[str, str] = {}
                mapped_fields_set = set()
                
                def _canon_target(t: Any) -> str:
                    raw = str(t or '').strip()
                    if not raw:
                        return raw
                    ln = raw.strip().lower().replace('_', ' ').strip()
                    if self.file_type == 'objects':
                        if ln in {'name','object name','group name','alias','label'}: return 'name'
                        if ln in {'type','object type','member type','category'}: return 'type'
                        if ln in {'ip','ip address','ip addr','address','ipv4','subnet','cidr'}: return 'ip_address'
                        if ln in {'interface','iface','intf','nic'}: return 'interface'
                        if ln in {'details','description','notes','comment'}: return 'details'
                    if ln in {'rule name'}: return 'rule_name'
                    if ln in {'protocol','proto'}: return 'protocol'
                    if ln in {'source','src','source ip','src ip'}: return 'source'
                    if ln in {'destination','dst','destination ip','dst ip'}: return 'destination'
                    if ln in {'source port','src port'}: return 'source_port'
                    if ln in {'destination port','dest port','dst port','port'}: return 'dest_port'
                    if ln in {'source zone','src zone','from zone'}: return 'source_zone'
                    if ln in {'destination zone','dest zone','dst zone','to zone'}: return 'dest_zone'
                    if ln in {'application','app','app name','application name'}: return 'application'
                    if ln in {'service'}: return 'service'
                    if ln in {'service port','service_port'}: return 'service_port'
                    if ln in {'port protocol','port_protocol'}: return 'port_protocol'
                    if ln in {'hostname','host name','host','asset name','device','node','server','vm name'}: return 'hostname'
                    if ln in {'ip address','ip','ipaddr','address','ipv4'}: return 'ip_address'
                    if ln in {'owner','application owner','asset owner','custodian'}: return 'owner'
                    if ln in {'department','dept','business unit','bu'}: return 'department'
                    if ln in {'environment','env','tier'}: return 'environment'
                    if ln in {'location','site','datacenter','dc','building','floor'}: return 'location'
                    if ln in {'asset type','category'}: return 'asset_type'
                    if ln in {'type'}: return 'asset_type' if self.file_type == 'cmdb' else 'type'
                    if ln in {'operating system','os'}: return 'operating_system'
                    if ln in {'os version','version'}: return 'os_version'
                    if ln in {'manufacturer','vendor'}: return 'manufacturer'
                    if ln in {'model'}: return 'model'
                    if ln in {'mac address','mac'}: return 'mac_address'
                    if ln in {'serial number','serial'}: return 'serial_number'
                    if ln in {'asset tag','tag','asset id'}: return 'asset_tag'
                    if ln in {'business unit','bu'}: return 'business_unit'
                    if ln in {'cost center'}: return 'cost_center'
                    if ln in {'status'}: return 'status'
                    if ln in {'description','desc','comment','notes','purpose'}: return 'description'
                    if ln in {'application name','service name'}: return 'application_name'
                    return raw
                
                for original_col, detected_field in detected_mapping.items():
                    if original_col in df.columns:
                        canon_target = _canon_target(detected_field)
                        rename_mapping[original_col] = canon_target
                        mapped_fields_set.add(canon_target)
                
                df_mapped = df.rename(columns=rename_mapping) if rename_mapping else df
                try:
                    df_mapped['_mapped_fields'] = [list(mapped_fields_set)] * len(df_mapped)
                except Exception:
                    pass
                return df_mapped
            return df
        except Exception as e:
            self.logger.warning(f"Intelligent mapping failed: {str(e)}, using original columns")
            return df
    
    def _clean_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Clean and validate parsed records
        
        Args:
            records: Raw parsed records
            
        Returns:
            Cleaned records
        """
        cleaned_records = []
        
        for i, record in enumerate(records):
            try:
                cleaned_record = self._clean_single_record(record)
                if cleaned_record:  # Skip empty records
                    cleaned_records.append(cleaned_record)
            except Exception as e:
                self.logger.warning(f"Skipping invalid record at row {i+1}: {str(e)}")
                continue
        
        return cleaned_records
    
    def _clean_single_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Clean a single record
        
        Args:
            record: Single record dictionary
            
        Returns:
            Cleaned record or None if invalid
        """
        cleaned = {}
        
        for key, value in record.items():
            # Preserve internal helper fields without coercion
            if key == '_mapped_fields' and isinstance(value, list):
                cleaned[key] = value
                continue
            if key == '_mapping_sources' and isinstance(value, dict):
                cleaned[key] = value
                continue
            if key == '_strict_mapping' and isinstance(value, (bool, int, str)):
                try:
                    cleaned[key] = bool(int(value)) if isinstance(value, str) else bool(value)
                except Exception:
                    cleaned[key] = True
                continue
            # Skip NaN values
            try:
                if pd.isna(value):
                    continue
            except (ValueError, TypeError):
                # Handle cases where pd.isna fails on arrays/lists
                if isinstance(value, list) and not value:
                    continue
                elif isinstance(value, list):
                    # For lists, check if any element is NaN
                    try:
                        if all(pd.isna(v) for v in value):
                            continue
                    except:
                        # If we can't evaluate, keep the value
                        pass
            
            # Convert to string and strip whitespace
            cleaned_value = str(value).strip()
            
            # Skip empty values
            if not cleaned_value:
                continue
            
            # Apply field-specific cleaning based on file type
            cleaned_value = self._clean_field_value(key, cleaned_value)
            
            if cleaned_value is not None:
                cleaned[key] = cleaned_value
        
        # Apply protocol/port parsing for combined service fields
        cleaned = self._enhance_with_protocol_port_parsing(cleaned)
        
        # Return None if record is empty after cleaning
        return cleaned if cleaned else None
    
    def _clean_field_value(self, field_name: str, value: str) -> Optional[str]:
        """
        Apply field-specific cleaning rules
        
        Args:
            field_name: Name of the field
            value: Field value
            
        Returns:
            Cleaned value or None if invalid
        """
        if not value or not value.strip():
            return None
        
        value = value.strip()
        
        # Field-specific cleaning rules
        if field_name in ['ip_address']:
            # Relax IP validation: keep value but warn if not IPv4
            import re
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if not re.match(ip_pattern, value):
                self.logger.warning(f"Non-standard IP address value retained: {value}")
                return value
        
        elif field_name in ['vlan_id']:
            # VLAN ID should be numeric
            try:
                vlan_id = int(value)
                if not (1 <= vlan_id <= 4094):
                    self.logger.warning(f"VLAN ID out of range: {vlan_id}")
                    return None
                return str(vlan_id)
            except ValueError:
                self.logger.warning(f"Invalid VLAN ID format: {value}")
                return None
        
        elif field_name in ['hostname']:
            # Basic hostname validation
            import re
            hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(hostname_pattern, value):
                self.logger.warning(f"Invalid hostname format: {value}")
                # Don't return None for hostname, just log warning
        
        return value
    
    def _enhance_with_protocol_port_parsing(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance record with protocol/port parsing for combined service fields
        
        Args:
            record: Cleaned record dictionary
            
        Returns:
            Enhanced record with parsed protocol/port information
        """
        # Common field names that might contain combined protocol/port data (prefer port-bearing fields first)
        service_fields = ['service_port', 'port_protocol', 'service', 'Service', 'proto', 'protocol']

        mapped_fields = set()
        try:
            mf = record.get('_mapped_fields') or []
            mapped_fields = {str(x).strip().lower() for x in (mf if isinstance(mf, list) else [])}
        except Exception:
            mapped_fields = set()
        allow_protocol = ('protocol' in mapped_fields) or ('service' in mapped_fields) or ('proto' in mapped_fields)
        allow_dest_port = ('dest_port' in mapped_fields) or ('destination port' in mapped_fields) or ('service' in mapped_fields) or ('service_port' in mapped_fields) or ('port_protocol' in mapped_fields)
        if not (allow_protocol or allow_dest_port):
            return record
        
        used_service_value = None
        for field_name in service_fields:
            if field_name in record and record[field_name]:
                used_service_value = str(record[field_name])
                record = enhance_row_with_protocol_port(
                    record,
                    field_name,
                    allow_protocol=allow_protocol,
                    allow_dest_port=allow_dest_port
                )
                break

        if not used_service_value:
            orig = record.get('original_row') or {}
            # Try to locate a service-like column in original row
            for k, v in orig.items():
                if isinstance(v, str) and v.strip():
                    kl = str(k).strip().lower()
                    if 'service' == kl or kl.startswith('service') or kl == 'svc':
                        used_service_value = v.strip()
                        break

        current_protocol = str(record.get('protocol') or '').upper()
        current_dest_port = str(record.get('dest_port') or '').strip()
        invalid_protocols = {'', 'ANY', 'ALLOW'}
        need_protocol = current_protocol in invalid_protocols or current_protocol not in {'TCP','UDP','ICMP','IP'}
        invalid_ports = {'', '-', 'None', 'NA', 'N/A'}
        need_port = (current_dest_port in invalid_ports)
        if (allow_dest_port and (record.get('dest_port') or used_service_value)) or (allow_protocol and used_service_value):
            from protocol_port_parser import resolve_protocol_port_from_mixed_field
            source_value = used_service_value if used_service_value else str(record.get('dest_port'))
            resolved = resolve_protocol_port_from_mixed_field(source_value)
            if allow_protocol and need_protocol and resolved.get('protocol'):
                record['protocol'] = resolved['protocol']
            # Only populate ports when missing/invalid; never merge over user-mapped values
            resolved_ports = str(resolved.get('dest_port') or '').strip()
            if resolved_ports:
                if allow_dest_port and need_port:
                    record['dest_port'] = resolved_ports
        else:
            if (allow_protocol and need_protocol) or (allow_dest_port and need_port):
                from protocol_port_parser import infer_protocol_port_from_record
                inferred = infer_protocol_port_from_record(record)
                if allow_protocol and need_protocol and inferred.get('protocol'):
                    record['protocol'] = inferred['protocol']
                if allow_dest_port and need_port and inferred.get('dest_port'):
                    record['dest_port'] = inferred['dest_port']
        
        return record
    
    def get_preview_data(self, max_rows: int = 5) -> List[Dict[str, Any]]:
        """
        Get preview data from the file for column mapping UI
        
        Args:
            max_rows: Maximum number of rows to return
            
        Returns:
            List of sample records
        """
        if not self.validate_file():
            return []
        
        try:
            # Read only first few rows
            if self.file_path.lower().endswith('.csv'):
                df = pd.read_csv(
                    self.file_path, 
                    encoding=self.encoding,
                    delimiter=self.delimiter,
                    nrows=max_rows
                )
            elif self.file_path.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(self.file_path, nrows=max_rows)
            else:
                return []
            
            # Convert to list of dictionaries
            return df.to_dict('records')
            
        except Exception as e:
            self.logger.error(f"Error getting preview data: {str(e)}")
            return []