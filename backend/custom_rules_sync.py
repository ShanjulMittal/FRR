"""
Custom Rules Sync Service
Synchronizes custom rules from SQLite to PostgreSQL ComplianceRule table
"""
import logging
from typing import List, Dict, Any
from models import db, ComplianceRule
from custom_fields_service import CustomFieldsService

logger = logging.getLogger(__name__)

class CustomRulesSyncService:
    """Service to sync custom rules to the main compliance system"""
    
    def __init__(self):
        self.custom_fields_service = CustomFieldsService()
    
    def sync_custom_rules_to_compliance(self) -> Dict[str, Any]:
        """
        Sync all active custom rules to the ComplianceRule table
        
        Returns:
            dict: {
                'synced_count': int,
                'updated_count': int,
                'errors': List[str]
            }
        """
        try:
            # Get all custom rules from SQLite
            custom_rules = self.custom_fields_service.get_all_rules()
            
            synced_count = 0
            updated_count = 0
            errors = []
            
            for custom_rule in custom_rules:
                try:
                    # Convert custom rule to compliance rule format
                    compliance_rule_data = self._convert_custom_rule_to_compliance(custom_rule)
                    
                    # Check if rule already exists (by name and field)
                    existing_rule = ComplianceRule.query.filter_by(
                        rule_name=compliance_rule_data['rule_name'],
                        field_to_check=compliance_rule_data['field_to_check']
                    ).first()
                    
                    if existing_rule:
                        # Update existing rule
                        for key, value in compliance_rule_data.items():
                            if key != 'rule_name':  # Don't update the name
                                setattr(existing_rule, key, value)
                        updated_count += 1
                        logger.info(f"Updated compliance rule: {existing_rule.rule_name}")
                    else:
                        # Create new rule
                        new_rule = ComplianceRule(**compliance_rule_data)
                        db.session.add(new_rule)
                        synced_count += 1
                        logger.info(f"Created new compliance rule: {new_rule.rule_name}")
                        
                except Exception as e:
                    error_msg = f"Error syncing custom rule {custom_rule.get('rule_name', 'unknown')}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            # Commit all changes
            db.session.commit()
            
            return {
                'synced_count': synced_count,
                'updated_count': updated_count,
                'errors': errors
            }
            
        except Exception as e:
            db.session.rollback()
            error_msg = f"Error during custom rules sync: {str(e)}"
            logger.error(error_msg)
            return {
                'synced_count': 0,
                'updated_count': 0,
                'errors': [error_msg]
            }
    
    def _convert_custom_rule_to_compliance(self, custom_rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a custom rule to ComplianceRule format
        
        Args:
            custom_rule: Custom rule from SQLite database
            
        Returns:
            dict: ComplianceRule compatible data
        """
        # Map custom rule condition types to compliance operators
        condition_operator_map = {
            'threshold': 'greater_than_or_equal',
            'range': 'in_range',
            'pattern': 'regex_match',
            'custom': 'equals'
        }
        
        # Get the operator
        operator = condition_operator_map.get(custom_rule['condition_type'], 'equals')
        
        # Format the field name with custom_ prefix
        field_name = f"custom_{custom_rule['field_name']}"
        
        # Create rule name that indicates it's from custom rules
        rule_name = f"Custom: {custom_rule['rule_name']}"
        
        return {
            'rule_name': rule_name,
            'description': f"Custom rule: {custom_rule.get('description', '')}",
            'field_to_check': field_name,
            'operator': operator,
            'value': custom_rule['condition_value'],
            'severity': custom_rule['severity'].title(),  # Ensure proper case
            'is_active': custom_rule.get('is_active', True),
            'created_by': custom_rule.get('created_by', 'custom_rules_sync')
        }
    
    def remove_synced_custom_rules(self) -> int:
        """
        Remove all compliance rules that were synced from custom rules
        
        Returns:
            int: Number of rules removed
        """
        try:
            # Find all compliance rules that start with "Custom:"
            custom_compliance_rules = ComplianceRule.query.filter(
                ComplianceRule.rule_name.like('Custom:%')
            ).all()
            
            count = len(custom_compliance_rules)
            
            for rule in custom_compliance_rules:
                db.session.delete(rule)
            
            db.session.commit()
            logger.info(f"Removed {count} synced custom rules from compliance table")
            
            return count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error removing synced custom rules: {str(e)}")
            return 0
    
    def get_sync_status(self) -> Dict[str, Any]:
        """
        Get the current sync status between custom rules and compliance rules
        
        Returns:
            dict: Status information
        """
        try:
            # Count custom rules
            custom_rules = self.custom_fields_service.get_all_rules()
            custom_rules_count = len(custom_rules)
            
            # Count synced compliance rules
            synced_rules_count = ComplianceRule.query.filter(
                ComplianceRule.rule_name.like('Custom:%')
            ).count()
            
            return {
                'custom_rules_count': custom_rules_count,
                'synced_rules_count': synced_rules_count,
                'sync_needed': custom_rules_count != synced_rules_count
            }
            
        except Exception as e:
            logger.error(f"Error getting sync status: {str(e)}")
            return {
                'custom_rules_count': 0,
                'synced_rules_count': 0,
                'sync_needed': True,
                'error': str(e)
            }

# Global instance
custom_rules_sync = CustomRulesSyncService()