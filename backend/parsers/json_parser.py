"""
JSON Parser - Handles JSON configuration files with validation
"""
import json
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser


class JSONParser(BaseParser):
    """Parser for JSON configuration files"""
    
    def __init__(self, file_path: str, file_type: str, **kwargs):
        super().__init__(file_path, file_type, **kwargs)
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.schema = kwargs.get('schema', None)
    
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse JSON file and return structured data
        
        Returns:
            List of dictionaries containing parsed data
        """
        if not self.validate_file():
            raise ValueError(f"Invalid file: {self.file_path}")
        
        self.log_parsing_start()
        
        try:
            with open(self.file_path, 'r', encoding=self.encoding) as file:
                data = json.load(file)
            
            # Convert to list format if needed
            records = self._normalize_json_data(data)
            
            # Validate records if schema is provided
            if self.schema:
                records = self._validate_records(records)
            
            # Clean and process records
            cleaned_records = self._clean_records(records)
            
            self.log_parsing_complete(len(cleaned_records))
            return cleaned_records
            
        except json.JSONDecodeError as e:
            self.handle_parsing_error(e, f"Invalid JSON format at line {e.lineno}, column {e.colno}")
        except Exception as e:
            self.handle_parsing_error(e, "JSON parsing")
    
    def _normalize_json_data(self, data: Any) -> List[Dict[str, Any]]:
        """
        Normalize JSON data to list of dictionaries
        
        Args:
            data: Raw JSON data
            
        Returns:
            List of dictionaries
        """
        if isinstance(data, list):
            # Already a list, ensure all items are dictionaries
            records = []
            for item in data:
                if isinstance(item, dict):
                    records.append(item)
                else:
                    self.logger.warning(f"Skipping non-dictionary item: {item}")
            return records
        
        elif isinstance(data, dict):
            # Check if it's a single record or contains arrays
            if self._is_single_record(data):
                return [data]
            else:
                # Try to extract arrays from the dictionary
                return self._extract_arrays_from_dict(data)
        
        else:
            raise ValueError(f"Unsupported JSON structure: {type(data)}")
    
    def _is_single_record(self, data: Dict[str, Any]) -> bool:
        """
        Check if dictionary represents a single record
        
        Args:
            data: Dictionary to check
            
        Returns:
            True if it's a single record
        """
        # If all values are simple types (not lists/dicts), it's likely a single record
        for value in data.values():
            if isinstance(value, (list, dict)):
                return False
        return True
    
    def _extract_arrays_from_dict(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract arrays from dictionary structure
        
        Args:
            data: Dictionary containing arrays
            
        Returns:
            List of records
        """
        records = []
        
        # Look for arrays in the dictionary
        for key, value in data.items():
            if isinstance(value, list) and value:
                # Check if list contains dictionaries
                if isinstance(value[0], dict):
                    # Add context from parent key
                    for item in value:
                        if isinstance(item, dict):
                            item['_source_key'] = key
                            records.append(item)
                        else:
                            self.logger.warning(f"Skipping non-dictionary item in {key}: {item}")
        
        # If no arrays found, treat the whole dict as a single record
        if not records:
            records = [data]
        
        return records
    
    def _validate_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate records against schema if provided
        
        Args:
            records: List of records to validate
            
        Returns:
            List of valid records
        """
        # This is a placeholder for schema validation
        # In a real implementation, you might use jsonschema library
        valid_records = []
        
        for i, record in enumerate(records):
            try:
                if self._validate_single_record(record):
                    valid_records.append(record)
                else:
                    self.logger.warning(f"Record {i+1} failed validation")
            except Exception as e:
                self.logger.warning(f"Error validating record {i+1}: {str(e)}")
        
        return valid_records
    
    def _validate_single_record(self, record: Dict[str, Any]) -> bool:
        """
        Validate a single record
        
        Args:
            record: Record to validate
            
        Returns:
            True if valid
        """
        # Basic validation based on file type
        if self.file_type == 'cmdb':
            return self._validate_cmdb_record(record)
        elif self.file_type == 'vlan':
            return self._validate_vlan_record(record)
        elif self.file_type == 'firewall':
            return self._validate_firewall_record(record)
        
        return True  # No specific validation
    
    def _validate_cmdb_record(self, record: Dict[str, Any]) -> bool:
        """Validate CMDB record"""
        required_fields = ['hostname', 'ip_address']
        return all(field in record and record[field] for field in required_fields)
    
    def _validate_vlan_record(self, record: Dict[str, Any]) -> bool:
        """Validate VLAN record"""
        required_fields = ['subnet']
        return all(field in record and record[field] for field in required_fields)
    
    def _validate_firewall_record(self, record: Dict[str, Any]) -> bool:
        """Validate firewall record"""
        required_fields = ['rule_text']
        return all(field in record and record[field] for field in required_fields)
    
    def _clean_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Clean and standardize records
        
        Args:
            records: Raw records
            
        Returns:
            Cleaned records
        """
        cleaned_records = []
        
        for i, record in enumerate(records):
            try:
                cleaned_record = self._clean_single_record(record)
                if cleaned_record:
                    cleaned_records.append(cleaned_record)
            except Exception as e:
                self.logger.warning(f"Error cleaning record {i+1}: {str(e)}")
        
        return cleaned_records
    
    def _clean_single_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Clean a single record
        
        Args:
            record: Record to clean
            
        Returns:
            Cleaned record or None if invalid
        """
        cleaned = {}
        
        for key, value in record.items():
            # Skip None values
            if value is None:
                continue
            
            # Convert to string and clean
            if isinstance(value, (str, int, float, bool)):
                cleaned_value = str(value).strip()
                if cleaned_value:
                    cleaned[key] = cleaned_value
            elif isinstance(value, (list, dict)):
                # Convert complex types to JSON string
                try:
                    cleaned[key] = json.dumps(value)
                except Exception:
                    self.logger.warning(f"Could not serialize complex value for key {key}")
        
        return cleaned if cleaned else None
    
    def get_schema_info(self) -> Dict[str, Any]:
        """
        Analyze JSON structure and return schema information
        
        Returns:
            Dictionary with schema information
        """
        if not self.validate_file():
            return {}
        
        try:
            with open(self.file_path, 'r', encoding=self.encoding) as file:
                data = json.load(file)
            
            return self._analyze_structure(data)
            
        except Exception as e:
            self.logger.error(f"Error analyzing JSON structure: {str(e)}")
            return {}
    
    def _analyze_structure(self, data: Any, path: str = "root") -> Dict[str, Any]:
        """
        Recursively analyze JSON structure
        
        Args:
            data: JSON data to analyze
            path: Current path in the structure
            
        Returns:
            Structure analysis
        """
        if isinstance(data, dict):
            structure = {
                "type": "object",
                "path": path,
                "keys": list(data.keys()),
                "properties": {}
            }
            
            for key, value in data.items():
                structure["properties"][key] = self._analyze_structure(
                    value, f"{path}.{key}"
                )
            
            return structure
        
        elif isinstance(data, list):
            structure = {
                "type": "array",
                "path": path,
                "length": len(data),
                "items": {}
            }
            
            if data:
                # Analyze first item as sample
                structure["items"] = self._analyze_structure(
                    data[0], f"{path}[0]"
                )
            
            return structure
        
        else:
            return {
                "type": type(data).__name__,
                "path": path,
                "sample_value": str(data)[:100]  # Truncate long values
            }