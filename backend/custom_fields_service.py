"""
Custom Fields Service for managing dynamic field definitions and rules
"""
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
import os

class CustomFieldsService:
    def __init__(self, db_path: str = None):
        if not db_path:
            base_dir = os.getenv('DATA_DIR')
            if not base_dir:
                base_dir = '/data' if os.path.isdir('/data') else os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, 'custom_fields.db')
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create custom_fields table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                field_name TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                description TEXT,
                field_type TEXT NOT NULL CHECK (field_type IN ('text', 'number', 'boolean', 'date', 'select')),
                file_type TEXT NOT NULL CHECK (file_type IN ('firewall', 'cmdb', 'vlan')),
                is_mandatory BOOLEAN DEFAULT FALSE,
                is_important BOOLEAN DEFAULT FALSE,
                default_value TEXT,
                validation_rules TEXT,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Create custom_rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                field_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                description TEXT,
                condition_type TEXT NOT NULL CHECK (condition_type IN ('threshold', 'range', 'pattern', 'custom')),
                condition_value TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('alert', 'block', 'flag', 'log')),
                severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                is_active BOOLEAN DEFAULT TRUE,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (field_id) REFERENCES custom_fields (id) ON DELETE CASCADE
            )
        ''')
        
        # Insert default hit count field if it doesn't exist
        cursor.execute('''
            INSERT OR IGNORE INTO custom_fields 
            (field_name, display_name, description, field_type, file_type, is_mandatory, is_important, created_by)
            VALUES 
            ('hit_count', 'Hit Count', 'Number of times a rule has been triggered', 'number', 'firewall', FALSE, TRUE, 'system')
        ''')
        # Ensure service_count field exists for firewall rules
        cursor.execute('''
            INSERT OR IGNORE INTO custom_fields 
            (field_name, display_name, description, field_type, file_type, is_mandatory, is_important, created_by)
            VALUES 
            ('service_count', 'Service Count', 'Number of distinct destination ports/services in rule', 'number', 'firewall', FALSE, TRUE, 'system')
        ''')
        # Ensure VPN field exists to capture VPN setting from uploads
        cursor.execute('''
            INSERT OR IGNORE INTO custom_fields 
            (field_name, display_name, description, field_type, file_type, is_mandatory, is_important, created_by)
            VALUES 
            ('vpn', 'VPN', 'VPN setting from uploaded firewall policy (e.g., Any)', 'text', 'firewall', FALSE, FALSE, 'system')
        ''')
        
        conn.commit()
        conn.close()
    
    def get_all_fields(self) -> List[Dict[str, Any]]:
        """Get all custom fields"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM custom_fields 
            WHERE is_active = TRUE 
            ORDER BY created_at DESC
        ''')
        
        fields = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return fields
    
    def get_field_by_id(self, field_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific field by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM custom_fields WHERE id = ? AND is_active = TRUE', (field_id,))
        row = cursor.fetchone()
        
        conn.close()
        return dict(row) if row else None
    
    def create_field(self, field_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new custom field"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO custom_fields 
                (field_name, display_name, description, field_type, file_type, 
                 is_mandatory, is_important, default_value, validation_rules, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                field_data['field_name'],
                field_data['display_name'],
                field_data.get('description', ''),
                field_data['field_type'],
                field_data['file_type'],
                field_data.get('is_mandatory', False),
                field_data.get('is_important', False),
                field_data.get('default_value'),
                field_data.get('validation_rules'),
                field_data['created_by']
            ))
            
            field_id = cursor.lastrowid
            conn.commit()
            
            # Return the created field
            return self.get_field_by_id(field_id)
            
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError(f"Field name already exists: {e}")
        finally:
            conn.close()
    
    def update_field(self, field_id: int, field_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing custom field"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE custom_fields 
                SET field_name = ?, display_name = ?, description = ?, field_type = ?, 
                    file_type = ?, is_mandatory = ?, is_important = ?, default_value = ?, 
                    validation_rules = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND is_active = TRUE
            ''', (
                field_data['field_name'],
                field_data['display_name'],
                field_data.get('description', ''),
                field_data['field_type'],
                field_data['file_type'],
                field_data.get('is_mandatory', False),
                field_data.get('is_important', False),
                field_data.get('default_value'),
                field_data.get('validation_rules'),
                field_id
            ))
            
            if cursor.rowcount == 0:
                raise ValueError("Field not found or already deleted")
            
            conn.commit()
            return self.get_field_by_id(field_id)
            
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError(f"Field name already exists: {e}")
        finally:
            conn.close()
    
    def delete_field(self, field_id: int) -> bool:
        """Soft delete a custom field"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE custom_fields 
            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (field_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Get all custom rules with field information"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, f.field_name, f.display_name as field_display_name
            FROM custom_rules r
            JOIN custom_fields f ON r.field_id = f.id
            WHERE r.is_active = TRUE AND f.is_active = TRUE
            ORDER BY r.created_at DESC
        ''')
        
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rules
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, f.field_name, f.display_name as field_display_name
            FROM custom_rules r
            JOIN custom_fields f ON r.field_id = f.id
            WHERE r.id = ? AND r.is_active = TRUE AND f.is_active = TRUE
        ''', (rule_id,))
        
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new custom rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO custom_rules 
                (field_id, rule_name, description, condition_type, condition_value, 
                 action, severity, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_data['field_id'],
                rule_data['rule_name'],
                rule_data.get('description', ''),
                rule_data['condition_type'],
                rule_data['condition_value'],
                rule_data['action'],
                rule_data['severity'],
                rule_data['created_by']
            ))
            
            rule_id = cursor.lastrowid
            conn.commit()
            
            return self.get_rule_by_id(rule_id)
            
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError(f"Error creating rule: {e}")
        finally:
            conn.close()
    
    def update_rule(self, rule_id: int, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing custom rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE custom_rules 
                SET field_id = ?, rule_name = ?, description = ?, condition_type = ?, 
                    condition_value = ?, action = ?, severity = ?
                WHERE id = ? AND is_active = TRUE
            ''', (
                rule_data['field_id'],
                rule_data['rule_name'],
                rule_data.get('description', ''),
                rule_data['condition_type'],
                rule_data['condition_value'],
                rule_data['action'],
                rule_data['severity'],
                rule_id
            ))
            
            if cursor.rowcount == 0:
                raise ValueError("Rule not found or already deleted")
            
            conn.commit()
            return self.get_rule_by_id(rule_id)
            
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError(f"Error updating rule: {e}")
        finally:
            conn.close()
    
    def delete_rule(self, rule_id: int) -> bool:
        """Soft delete a custom rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE custom_rules 
            SET is_active = FALSE 
            WHERE id = ?
        ''', (rule_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    def get_fields_by_file_type(self, file_type: str) -> List[Dict[str, Any]]:
        """Get all active fields for a specific file type"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM custom_fields 
            WHERE file_type = ? AND is_active = TRUE 
            ORDER BY is_mandatory DESC, is_important DESC, display_name
        ''', (file_type,))
        
        fields = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return fields
    
    def evaluate_rules(self, field_name: str, value: Any) -> List[Dict[str, Any]]:
        """Evaluate rules for a specific field and value"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, f.field_name, f.display_name as field_display_name, f.field_type
            FROM custom_rules r
            JOIN custom_fields f ON r.field_id = f.id
            WHERE f.field_name = ? AND r.is_active = TRUE AND f.is_active = TRUE
        ''', (field_name,))
        
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        triggered_rules = []
        
        for rule in rules:
            if self._evaluate_condition(rule, value):
                triggered_rules.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['rule_name'],
                    'description': rule['description'],
                    'action': rule['action'],
                    'severity': rule['severity'],
                    'field_name': rule['field_name'],
                    'field_display_name': rule['field_display_name'],
                    'triggered_value': value
                })
        
        return triggered_rules
    
    def _evaluate_condition(self, rule: Dict[str, Any], value: Any) -> bool:
        """Evaluate if a rule condition is met"""
        condition_type = rule['condition_type']
        condition_value = rule['condition_value']
        field_type = rule['field_type']
        
        try:
            if field_type == 'number':
                value = float(value) if value is not None else 0
                
                if condition_type == 'threshold':
                    threshold = float(condition_value)
                    return value >= threshold
                elif condition_type == 'range':
                    # Format: "min,max"
                    min_val, max_val = map(float, condition_value.split(','))
                    return min_val <= value <= max_val
                    
            elif field_type == 'text':
                value_str = str(value) if value is not None else ''
                
                if condition_type == 'pattern':
                    import re
                    return bool(re.search(condition_value, value_str, re.IGNORECASE))
                    
            elif field_type == 'boolean':
                bool_value = bool(value)
                expected = condition_value.lower() == 'true'
                return bool_value == expected
                
            # Custom condition evaluation can be extended here
            if condition_type == 'custom':
                # For now, just return False for custom conditions
                # This can be extended to support custom Python expressions
                return False
                
        except (ValueError, TypeError, AttributeError):
            return False
        
        return False
