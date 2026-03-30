"""
Base Parser Class - Abstract base class for all file parsers
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Abstract base class for all file parsers"""
    
    def __init__(self, file_path: str, file_type: str, **kwargs):
        """
        Initialize the parser
        
        Args:
            file_path: Path to the file to be parsed
            file_type: Type of file ('firewall', 'cmdb', 'vlan')
            **kwargs: Additional parser-specific arguments
        """
        self.file_path = file_path
        self.file_type = file_type
        self.kwargs = kwargs
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse the file and return structured data
        
        Returns:
            List of dictionaries containing parsed data
        """
        pass
    
    def validate_file(self) -> bool:
        """
        Validate that the file exists and is readable
        
        Returns:
            True if file is valid, False otherwise
        """
        import os
        
        if not os.path.exists(self.file_path):
            self.logger.error(f"File does not exist: {self.file_path}")
            return False
        
        if not os.path.isfile(self.file_path):
            self.logger.error(f"Path is not a file: {self.file_path}")
            return False
        
        if not os.access(self.file_path, os.R_OK):
            self.logger.error(f"File is not readable: {self.file_path}")
            return False
        
        return True
    
    def get_file_size(self) -> int:
        """Get file size in bytes"""
        import os
        return os.path.getsize(self.file_path)
    
    def log_parsing_start(self):
        """Log the start of parsing process"""
        self.logger.info(f"Starting to parse {self.file_type} file: {self.file_path}")
    
    def log_parsing_complete(self, record_count: int):
        """Log the completion of parsing process"""
        self.logger.info(f"Completed parsing {self.file_path}. Processed {record_count} records.")
    
    def handle_parsing_error(self, error: Exception, context: str = ""):
        """Handle and log parsing errors"""
        error_msg = f"Error parsing {self.file_path}"
        if context:
            error_msg += f" ({context})"
        error_msg += f": {str(error)}"
        
        self.logger.error(error_msg)
        raise ValueError(error_msg) from error