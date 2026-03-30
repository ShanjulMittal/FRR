"""
Parser Factory - Selects the appropriate parser based on file type and extension
"""
import os
import json
from typing import Dict, List, Any, Optional
from .csv_parser import CSVParser
from .json_parser import JSONParser
from .firewall_parser import FirewallParser


class ParserFactory:
    """Factory class to create appropriate parsers based on file type and extension"""
    
    def __init__(self):
        self.parsers = {
            'csv': CSVParser,
            'excel': CSVParser,  # CSVParser handles both CSV and Excel
            'json': JSONParser,
            'firewall': FirewallParser,
        }
    
    def get_parser(self, file_path: str, file_type: str, **kwargs):
        """
        Get the appropriate parser for the given file
        
        Args:
            file_path: Path to the file to be parsed
            file_type: Type of file ('firewall', 'cmdb', 'vlan')
            **kwargs: Additional arguments like column_mapping
            
        Returns:
            Parser instance
        """
        file_extension = self._get_file_extension(file_path)
        
        # Determine parser type based on file extension and type
        if file_extension in ['csv', 'xlsx', 'xls']:
            parser_type = 'csv'
        elif file_extension == 'json':
            parser_type = 'json'
        elif file_extension in ['txt', 'conf']:
            parser_type = 'firewall'
        else:
            raise ValueError(f"Unsupported file extension: {file_extension}")
        
        parser_class = self.parsers.get(parser_type)
        if not parser_class:
            raise ValueError(f"No parser available for type: {parser_type}")
        
        return parser_class(file_path, file_type, **kwargs)
    
    def _get_file_extension(self, file_path: str) -> str:
        """Extract file extension from file path"""
        return os.path.splitext(file_path)[1][1:].lower()
    
    def parse_file(self, file_path: str, file_type: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Parse a file using the appropriate parser
        
        Args:
            file_path: Path to the file to be parsed
            file_type: Type of file ('firewall', 'cmdb', 'vlan')
            **kwargs: Additional arguments like column_mapping
            
        Returns:
            List of parsed records
        """
        parser = self.get_parser(file_path, file_type, **kwargs)
        return parser.parse()


# Global parser factory instance
parser_factory = ParserFactory()