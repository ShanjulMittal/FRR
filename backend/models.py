from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

# Create a separate db instance that will be initialized by app
db = SQLAlchemy()

class RawFirewallRule(db.Model):
    """Stores original parsed firewall rules"""
    __tablename__ = 'raw_firewall_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    source_file = db.Column(db.String(255), nullable=False)
    file_line_number = db.Column(db.Integer)
    rule_type = db.Column(db.String(50))  # access_list, nat, object_group, etc.
    raw_text = db.Column(db.Text, nullable=False)  # Complete original rule text from file
    rule_text = db.Column(db.Text)  # Processed rule text for display (set during import)
    rule_name = db.Column(db.String(100))  # Rule name from CSV (e.g., WEB_ALLOW, SSH_BLOCK)
    vendor = db.Column(db.String(50))  # cisco_asa, palo_alto, fortinet, etc.
    
    # Parsed fields for access-list rules
    acl_name = db.Column(db.String(100))
    line_number_in_acl = db.Column(db.Integer)
    action = db.Column(db.String(20))  # permit, deny
    is_disabled = db.Column(db.Boolean, default=False)
    protocol = db.Column(db.String(20))  # tcp, udp, icmp, ip
    source = db.Column(db.String(255))
    destination = db.Column(db.String(255))
    source_port = db.Column(db.String(50))
    dest_port = db.Column(db.String(50))
    source_zone = db.Column(db.String(100))
    dest_zone = db.Column(db.String(100))
    application = db.Column(db.String(100))
    hit_count = db.Column(db.Integer)
    source_vlan_id = db.Column(db.Integer)
    source_vlan_name = db.Column(db.String(255))
    dest_vlan_id = db.Column(db.Integer)
    dest_vlan_name = db.Column(db.String(255))
    
    # Parsed fields for NAT rules
    inside_interface = db.Column(db.String(50))
    outside_interface = db.Column(db.String(50))
    nat_id = db.Column(db.Integer)
    translation_type = db.Column(db.String(20))  # static, dynamic
    real_source = db.Column(db.String(255))
    mapped_source = db.Column(db.String(255))
    real_destination = db.Column(db.String(255))
    mapped_destination = db.Column(db.String(255))
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        # Build a comprehensive raw_data dict to expose all stored columns
        raw_data = {
            'id': self.id,
            'source_file': self.source_file,
            'file_line_number': self.file_line_number,
            'rule_type': self.rule_type,
            'raw_text': self.raw_text,
            'rule_text': self.rule_text,
            'rule_name': self.rule_name,
            'vendor': self.vendor,
            'acl_name': self.acl_name,
            'line_number_in_acl': self.line_number_in_acl,
            'action': self.action,
            'is_disabled': self.is_disabled,
            'protocol': self.protocol,
            'source': self.source,
            'destination': self.destination,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'source_zone': self.source_zone,
            'dest_zone': self.dest_zone,
            'application': self.application,
            'hit_count': self.hit_count,
            'source_vlan_id': self.source_vlan_id,
            'source_vlan_name': self.source_vlan_name,
            'dest_vlan_id': self.dest_vlan_id,
            'dest_vlan_name': self.dest_vlan_name,
            'is_disabled': self.is_disabled,
            'inside_interface': self.inside_interface,
            'outside_interface': self.outside_interface,
            'nat_id': self.nat_id,
            'translation_type': self.translation_type,
            'real_source': self.real_source,
            'mapped_source': self.mapped_source,
            'real_destination': self.real_destination,
            'mapped_destination': self.mapped_destination,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        return {
            'id': self.id,
            'source_file': self.source_file,
            'file_line_number': self.file_line_number,
            'rule_type': self.rule_type,
            'raw_text': self.raw_text,
            'rule_text': self.rule_text,
            'rule_name': self.rule_name,
            'vendor': self.vendor,
            'acl_name': self.acl_name,
            'line_number_in_acl': self.line_number_in_acl,
            'action': self.action,
            'protocol': self.protocol,
            'source': self.source,
            'destination': self.destination,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'source_zone': self.source_zone,
            'dest_zone': self.dest_zone,
            'application': self.application,
            'hit_count': self.hit_count,
            'source_vlan_id': self.source_vlan_id,
            'source_vlan_name': self.source_vlan_name,
            'dest_vlan_id': self.dest_vlan_id,
            'dest_vlan_name': self.dest_vlan_name,
            'is_disabled': self.is_disabled,
            'inside_interface': self.inside_interface,
            'outside_interface': self.outside_interface,
            'nat_id': self.nat_id,
            'translation_type': self.translation_type,
            'real_source': self.real_source,
            'mapped_source': self.mapped_source,
            'real_destination': self.real_destination,
            'mapped_destination': self.mapped_destination,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'raw_data': raw_data
        }

class CMDBAsset(db.Model):
    """Stores CMDB inventory information"""
    __tablename__ = 'cmdb_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    source_file = db.Column(db.String(255), nullable=False)
    
    # Asset identification
    hostname = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))  # Support IPv6
    mac_address = db.Column(db.String(17))
    asset_tag = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    
    # Asset details
    asset_type = db.Column(db.String(100))  # server, workstation, network_device, etc.
    operating_system = db.Column(db.String(100))
    os_version = db.Column(db.String(50))
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    
    # Organizational information
    owner = db.Column(db.String(255))
    department = db.Column(db.String(100))
    location = db.Column(db.String(255))
    environment = db.Column(db.String(50))  # production, staging, development, etc.
    business_unit = db.Column(db.String(100))
    cost_center = db.Column(db.String(50))
    
    # Status and lifecycle
    status = db.Column(db.String(50), default='active')  # active, inactive, decommissioned, etc.
    purchase_date = db.Column(db.Date)
    warranty_expiry = db.Column(db.Date)
    last_scan_date = db.Column(db.DateTime)
    
    # Additional data (JSON field for flexible attributes)
    additional_data = db.Column(db.Text)  # JSON string
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        additional_data = {}
        if self.additional_data:
            try:
                additional_data = json.loads(self.additional_data)
            except json.JSONDecodeError:
                pass
        
        return {
            'id': self.id,
            'source_file': self.source_file,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'asset_tag': self.asset_tag,
            'serial_number': self.serial_number,
            'asset_type': self.asset_type,
            'operating_system': self.operating_system,
            'os_version': self.os_version,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'owner': self.owner,
            'department': self.department,
            'location': self.location,
            'environment': self.environment,
            'business_unit': self.business_unit,
            'cost_center': self.cost_center,
            'status': self.status,
            'purchase_date': self.purchase_date.isoformat() if self.purchase_date else None,
            'warranty_expiry': self.warranty_expiry.isoformat() if self.warranty_expiry else None,
            'last_scan_date': self.last_scan_date.isoformat() if self.last_scan_date else None,
            'additional_data': additional_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class VLANNetwork(db.Model):
    """Stores VLAN network information"""
    __tablename__ = 'vlan_networks'
    
    id = db.Column(db.Integer, primary_key=True)
    source_file = db.Column(db.String(255), nullable=False)
    
    # VLAN identification
    vlan_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    
    # Network information
    subnet = db.Column(db.String(50))  # CIDR notation
    gateway = db.Column(db.String(45))
    dhcp_enabled = db.Column(db.Boolean, default=False)
    dhcp_range_start = db.Column(db.String(45))
    dhcp_range_end = db.Column(db.String(45))
    
    # VLAN configuration
    vlan_type = db.Column(db.String(50))  # access, trunk, voice, etc.
    status = db.Column(db.String(20))  # active, inactive
    mtu = db.Column(db.Integer)
    
    # Organizational information
    location = db.Column(db.String(255))
    department = db.Column(db.String(100))
    environment = db.Column(db.String(50))
    business_unit = db.Column(db.String(100))
    
    # Security and access control
    security_zone = db.Column(db.String(100))
    access_control_list = db.Column(db.String(255))
    
    # Additional data (JSON field for flexible attributes)
    additional_data = db.Column(db.Text)  # JSON string
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        additional_data = {}
        if self.additional_data:
            try:
                additional_data = json.loads(self.additional_data)
            except json.JSONDecodeError:
                pass
        
        return {
            'id': self.id,
            'source_file': self.source_file,
            'vlan_id': self.vlan_id,
            'name': self.name,
            'description': self.description,
            'subnet': self.subnet,
            'gateway': self.gateway,
            'dhcp_enabled': self.dhcp_enabled,
            'dhcp_range_start': self.dhcp_range_start,
            'dhcp_range_end': self.dhcp_range_end,
            'vlan_type': self.vlan_type,
            'status': self.status,
            'mtu': self.mtu,
            'location': self.location,
            'department': self.department,
            'environment': self.environment,
            'business_unit': self.business_unit,
            'security_zone': self.security_zone,
            'access_control_list': self.access_control_list,
            'additional_data': additional_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ObjectGroup(db.Model):
    """Stores object groups (network and service groups)"""
    __tablename__ = 'object_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    source_file = db.Column(db.String(255), nullable=False)
    file_line_number = db.Column(db.Integer)
    
    # Object group identification
    name = db.Column(db.String(255), nullable=False)
    group_type = db.Column(db.String(50), nullable=False)  # network, service
    protocol = db.Column(db.String(20))  # For service groups: tcp, udp, etc.
    vendor = db.Column(db.String(50))
    
    # Group description
    description = db.Column(db.Text)
    
    # Status for Phase 3 workflow
    status = db.Column(db.String(20), default='unresolved')  # unresolved, resolved
    
    # Members (stored as JSON array)
    members = db.Column(db.Text)  # JSON string containing array of members
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        # Use the relationship to get member objects
        member_objs = self.member_details
        
        # Calculate derived fields for UI
        member_count = len(member_objs)
        member_values_preview = [m.member_value for m in member_objs[:5]]
        
        # Convert member objects to dicts
        members_list = [m.to_dict() for m in member_objs]
        
        return {
            'id': self.id,
            'source_file': self.source_file,
            'file_line_number': self.file_line_number,
            'name': self.name,
            'group_type': self.group_type,
            'protocol': self.protocol,
            'vendor': self.vendor,
            'description': self.description,
            'status': self.status,
            'members': members_list,
            'member_count': member_count,
            'member_values_preview': member_values_preview,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ObjectGroupMember(db.Model):
    """Stores individual members of object groups for detailed tracking"""
    __tablename__ = 'object_group_members'
    
    id = db.Column(db.Integer, primary_key=True)
    object_group_id = db.Column(db.Integer, db.ForeignKey('object_groups.id'), nullable=False)
    
    # Member details
    member_type = db.Column(db.String(20), nullable=False)  # ip, subnet, host, service, port
    member_value = db.Column(db.String(255), nullable=False)  # The actual IP, subnet, hostname, etc.
    
    # Additional context
    description = db.Column(db.Text)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    object_group = db.relationship('ObjectGroup', backref=db.backref('member_details', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'object_group_id': self.object_group_id,
            'member_type': self.member_type,
            'member_value': self.member_value,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ServicePortMapping(db.Model):
    """Stores service-to-port mappings for common network services"""
    __tablename__ = 'service_port_mappings'
    
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), nullable=False, unique=True)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # tcp, udp, both
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # web, mail, file_transfer, remote_access, etc.
    is_well_known = db.Column(db.Boolean, default=True)  # True for IANA well-known ports (0-1023)
    is_active = db.Column(db.Boolean, default=True)  # Allow enabling/disabling mappings
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'service_name': self.service_name,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'description': self.description,
            'category': self.category,
            'is_well_known': self.is_well_known,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class NormalizedRule(db.Model):
    """Stores normalized firewall rules with expanded object groups and enriched data"""
    __tablename__ = 'normalized_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    raw_rule_id = db.Column(db.Integer, db.ForeignKey('raw_firewall_rules.id'), nullable=False)
    
    # Basic rule information
    source_file = db.Column(db.String(255), nullable=False)
    rule_name = db.Column(db.String(100))  # Rule name from CSV (e.g., WEB_ALLOW, SSH_BLOCK)
    rule_type = db.Column(db.String(50))
    action = db.Column(db.String(20))  # permit, deny
    is_disabled = db.Column(db.Boolean, default=False)
    protocol = db.Column(db.String(20))  # tcp, udp, icmp, ip
    source_zone = db.Column(db.String(100))
    
    # Normalized source information
    source_ip = db.Column(db.String(45))  # Expanded from object groups
    source_ip_with_zone = db.Column(db.String(200))  # Source IP with zone AND logic
    source_port = db.Column(db.String(50))
    source_hostname = db.Column(db.String(255))  # From CMDB
    source_owner = db.Column(db.String(255))  # From CMDB
    source_department = db.Column(db.String(100))  # From CMDB
    source_environment = db.Column(db.String(50))  # From CMDB
    source_vlan_id = db.Column(db.Integer)  # From VLAN data
    source_vlan_name = db.Column(db.String(255))  # From VLAN data
    source_subnet = db.Column(db.String(50))  # From VLAN data
    source_location = db.Column(db.String(255))  # From VLAN data
    application = db.Column(db.String(100))
    
    # Normalized destination information
    dest_ip = db.Column(db.String(45))  # Expanded from object groups
    dest_ip_with_zone = db.Column(db.String(200))  # Destination IP with zone AND logic
    dest_port = db.Column(db.String(50))
    dest_zone = db.Column(db.String(100))
    dest_hostname = db.Column(db.String(255))  # From CMDB
    dest_owner = db.Column(db.String(255))  # From CMDB
    dest_department = db.Column(db.String(100))  # From CMDB
    dest_environment = db.Column(db.String(50))  # From CMDB
    dest_vlan_id = db.Column(db.Integer)  # From VLAN data
    dest_vlan_name = db.Column(db.String(255))  # From VLAN data
    dest_subnet = db.Column(db.String(50))  # From VLAN data
    dest_location = db.Column(db.String(255))  # From VLAN data
    
    # Service information (expanded from service object groups)
    service_name = db.Column(db.String(100))
    service_port = db.Column(db.String(50))
    service_protocol = db.Column(db.String(20))
    hit_count = db.Column(db.Integer)
    
    # Risk and compliance flags
    risk_level = db.Column(db.String(20))  # low, medium, high, critical
    compliance_status = db.Column(db.String(50))  # compliant, non_compliant, needs_review
    
    # Application metadata and annotations (editable by users)
    review_status = db.Column(db.String(50), default='pending')  # pending, approved, rejected, needs_review
    notes = db.Column(db.Text)  # User annotations and comments
    owner_approval = db.Column(db.String(100))  # Who approved this rule
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete flag
    
    # Custom fields data (JSON storage for dynamic fields)
    custom_fields_data = db.Column(db.Text)  # JSON string containing custom field values
    
    # Metadata
    normalization_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    raw_rule = db.relationship('RawFirewallRule', backref=db.backref('normalized_rules', lazy=True))
    
    def to_dict(self):
        import traceback
        import logging
        import ipaddress
        import re
        import json
        
        try:
            # Get raw rule data if available - avoid circular reference
            raw_text = None
            rule_text = None
            raw_data = None
            if self.raw_rule_id:
                # Use direct query to avoid relationship access
                from sqlalchemy import text
                raw_query = text("SELECT * FROM raw_firewall_rules WHERE id = :rule_id")
                raw_result = db.session.execute(raw_query, {'rule_id': self.raw_rule_id}).fetchone()
                
                if raw_result:
                    raw_text = raw_result.raw_text
                    rule_text = raw_result.rule_text
                    try:
                        if (raw_text is None or str(raw_text).strip() == '') and rule_text:
                            raw_text = rule_text
                    except Exception:
                        pass
                    raw_data = {
                        'id': raw_result.id,
                        'source_file': raw_result.source_file,
                        'file_line_number': raw_result.file_line_number,
                        'rule_type': raw_result.rule_type,
                        'raw_text': raw_result.raw_text,
                        'rule_text': raw_result.rule_text,
                        'rule_name': raw_result.rule_name,
                        'vendor': raw_result.vendor,
                        'acl_name': raw_result.acl_name,
                        'line_number_in_acl': raw_result.line_number_in_acl,
                        'action': raw_result.action,
                        'protocol': raw_result.protocol,
                        'source': raw_result.source,
                        'destination': raw_result.destination,
                        'source_port': raw_result.source_port,
                        'dest_port': raw_result.dest_port,
                        'inside_interface': raw_result.inside_interface,
                        'outside_interface': raw_result.outside_interface,
                        'nat_id': raw_result.nat_id,
                        'translation_type': raw_result.translation_type,
                        'real_source': raw_result.real_source,
                        'mapped_source': raw_result.mapped_source,
                        'real_destination': raw_result.real_destination,
                        'mapped_destination': raw_result.mapped_destination,
                        'created_at': raw_result.created_at if raw_result.created_at else None,
                        'updated_at': raw_result.updated_at if raw_result.updated_at else None
                    }
        except Exception as e:
            logging.error(f"Error in to_dict raw_data section: {str(e)}")
            logging.error(f"Full traceback: {traceback.format_exc()}")
            # Don't re-raise as circular reference, just set defaults
            raw_text = None
            raw_data = None
        
        # Get compliance information with review profile details - avoid circular references
        compliance_reasons = []
        compliance_profile_info = None
        
        try:
            # Use direct SQL queries to avoid circular references
            from sqlalchemy import text
            
            # Get review results with profile and compliance rule data
            query = text("""
                SELECT rr.status, rr.failed_checks, rr.severity,
                       rp.profile_name, rp.description as profile_description, rp.compliance_framework,
                       cr.rule_name, cr.description as rule_description
                FROM review_results rr
                LEFT JOIN review_profiles rp ON rr.profile_id = rp.id
                LEFT JOIN compliance_rules cr ON rr.compliance_rule_id = cr.id
                WHERE rr.normalized_rule_id = :rule_id
            """)
            
            result = db.session.execute(query, {'rule_id': self.id})
            review_data = result.fetchall()
        except Exception as e:
            logging.error(f"Error in to_dict compliance section: {str(e)}")
            logging.error(f"Full traceback: {traceback.format_exc()}")
            # Don't re-raise as circular reference, just set defaults
            review_data = []
        
        if review_data:
            # Group by profile to show compliance status per profile
            profiles_status = {}
            for row in review_data:
                profile_name = row.profile_name or "Unknown Profile"
                
                if profile_name not in profiles_status:
                    profiles_status[profile_name] = {
                        'profile_name': profile_name,
                        'profile_description': row.profile_description,
                        'compliance_framework': row.compliance_framework,
                        'overall_status': 'compliant',
                        'failed_checks': []
                    }
                
                if row.status == 'non_compliant':
                    profiles_status[profile_name]['overall_status'] = 'non_compliant'
                    
                    # Parse failed checks
                    failed_checks = json.loads(row.failed_checks) if row.failed_checks else []
                    
                    for check in failed_checks:
                        compliance_reasons.append({
                            'rule_name': row.rule_name or "Unknown Rule",
                            'description': row.rule_description,
                            'severity': row.severity,
                            'failed_check': check,
                            'profile_name': profile_name,
                            'compliance_framework': row.compliance_framework
                        })
                        
                        profiles_status[profile_name]['failed_checks'].append({
                            'rule_name': row.rule_name or "Unknown Rule",
                            'description': row.rule_description,
                            'severity': row.severity,
                            'failed_check': check
                        })
            
            # Set the main compliance profile info (use the first profile or the one with failures)
            if profiles_status:
                # Prefer non-compliant profiles for display, otherwise use the first one
                non_compliant_profiles = [p for p in profiles_status.values() if p['overall_status'] == 'non_compliant']
                if non_compliant_profiles:
                    compliance_profile_info = non_compliant_profiles[0]
                else:
                    compliance_profile_info = list(profiles_status.values())[0]
                
                # Add all profiles info
                compliance_profile_info['all_profiles'] = list(profiles_status.values())
        
        # Format compliance status with profile information
        formatted_compliance_status = self.compliance_status
        if compliance_profile_info:
            profile_name = compliance_profile_info['profile_name']
            framework = compliance_profile_info.get('compliance_framework', '')
            framework_text = f" ({framework})" if framework else ""
            
            if self.compliance_status == 'non_compliant':
                formatted_compliance_status = f"Non-Compliant against {profile_name}{framework_text}"
            elif self.compliance_status == 'compliant':
                formatted_compliance_status = f"Compliant with {profile_name}{framework_text}"
            else:
                formatted_compliance_status = f"Review Needed for {profile_name}{framework_text}"
        
        # Compute CMDB matches for source/destination IPs, including CIDR/range support
        def _collect_cmdb_matches(ip_field: str):
            matches = []
            try:
                if not ip_field:
                    return matches
                # Support semicolon-delimited multiple tokens
                tokens = [t.strip() for t in ip_field.split(';')] if ';' in ip_field else [ip_field]
                for token in tokens:
                    if not token:
                        continue
                    t_clean = re.sub(r'^(?:object-group\s+|object\s+)?', '', str(token), flags=re.IGNORECASE).strip()
                    t_clean = re.sub(r'^(?:range[_\s-]?|host[_\s-]?|h[_\s-]?|subnet[_\s-]?|network[_\s-]?)','', t_clean, flags=re.IGNORECASE).strip()
                    m_r_full = re.fullmatch(r"(?i)R_(\d{1,3}(?:\.\d{1,3}){3})[-_](\d{1,3}(?:\.\d{1,3}){3})", t_clean)
                    m_r_last = re.fullmatch(r"(?i)R_((?:\d{1,3}\.){3})(\d{1,3})[-_](\d{1,3})", t_clean)
                    if m_r_full or m_r_last:
                        try:
                            if m_r_full:
                                left = m_r_full.group(1)
                                right = m_r_full.group(2)
                            else:
                                prefix = m_r_last.group(1)
                                d_start = m_r_last.group(2)
                                d_end = m_r_last.group(3)
                                left = f"{prefix}{d_start}"
                                right = f"{prefix}{d_end}"
                            start_ip = ipaddress.ip_address(left)
                            end_ip = ipaddress.ip_address(right)
                            assets = db.session.query(CMDBAsset).all()
                            for a in assets:
                                if not a.ip_address:
                                    continue
                                try:
                                    ip = ipaddress.ip_address(a.ip_address)
                                    if start_ip <= ip <= end_ip:
                                        app = None
                                        pci = None
                                        try:
                                            add = json.loads(a.additional_data) if a.additional_data else {}
                                            app = add.get('application') or add.get('application_name') or add.get('app') or add.get('service') or add.get('service_name')
                                            pci = add.get('pcidss_asset_category')
                                        except Exception:
                                            app = None
                                            pci = None
                                        matches.append({
                                            'hostname': a.hostname,
                                            'ip_address': a.ip_address,
                                            'owner': a.owner,
                                            'department': a.department,
                                            'environment': a.environment,
                                            'asset_type': a.asset_type,
                                            'operating_system': a.operating_system,
                                            'model': a.model,
                                            'manufacturer': a.manufacturer,
                                            'location': a.location,
                                            'business_unit': a.business_unit,
                                            'application': app,
                                            'pcidss_asset_category': pci
                                        })
                                except Exception:
                                    continue
                            continue
                        except Exception:
                            pass
                    m_mask = re.fullmatch(r'(\d{1,3}(?:\.\d{1,3}){3})(?:[_]|M|-)(\d{1,2})', t_clean)
                    if m_mask:
                        ip_part = m_mask.group(1)
                        prefix = m_mask.group(2)
                        try:
                            p = int(prefix)
                            if 0 <= p <= 32:
                                t_clean = f"{ip_part}/{p}"
                        except Exception:
                            pass
                    m_cidr_dash = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,2})", t_clean)
                    if m_cidr_dash:
                        try:
                            p = int(m_cidr_dash.group(2))
                            if 0 <= p <= 32:
                                t_clean = f"{m_cidr_dash.group(1)}/{p}"
                        except Exception:
                            pass
                    if '/' in t_clean:
                        try:
                            network = ipaddress.ip_network(t_clean, strict=False)
                            # Narrow candidate set using LIKE on IPv4 octet prefixes when possible
                            assets = []
                            try:
                                if isinstance(network, ipaddress.IPv4Network):
                                    full_octets = network.prefixlen // 8
                                    if full_octets >= 1:
                                        base_octets = network.network_address.exploded.split('.')[:full_octets]
                                        prefix = '.'.join(base_octets) + '.'
                                        assets = db.session.query(CMDBAsset).filter(CMDBAsset.ip_address.like(f"{prefix}%")).all()
                                else:
                                    # IPv6: scan all for now
                                    assets = db.session.query(CMDBAsset).all()
                            except Exception:
                                assets = db.session.query(CMDBAsset).all()
                            for a in assets:
                                if not a.ip_address:
                                    continue
                                try:
                                    ip = ipaddress.ip_address(a.ip_address)
                                    if ip in network:
                                        app = None
                                        pci = None
                                        try:
                                            add = json.loads(a.additional_data) if a.additional_data else {}
                                            app = add.get('application') or add.get('application_name') or add.get('app') or add.get('service') or add.get('service_name')
                                            pci = add.get('pcidss_asset_category')
                                        except Exception:
                                            app = None
                                            pci = None
                                        matches.append({
                                            'hostname': a.hostname,
                                            'ip_address': a.ip_address,
                                            'owner': a.owner,
                                            'department': a.department,
                                            'environment': a.environment,
                                            'asset_type': a.asset_type,
                                            'operating_system': a.operating_system,
                                            'model': a.model,
                                            'manufacturer': a.manufacturer,
                                            'location': a.location,
                        						'business_unit': a.business_unit,
                                            'application': app,
                                            'pcidss_asset_category': pci
                                        })
                                except Exception:
                                    continue
                            continue
                        except Exception:
                            pass
                    # Possible dash range or IP-label pattern
                    if '-' in t_clean:
                        parts = [p.strip() for p in t_clean.split('-')]
                        if len(parts) == 2:
                            left, right = parts
                            try:
                                start_ip = ipaddress.ip_address(left)
                                # If right is a full IP, use it directly
                                try:
                                    end_ip = ipaddress.ip_address(right)
                                except Exception:
                                    # Support shorthand ranges like a.b.c.X-Y and a.b.c.X-c.Y
                                    left_octets = left.split('.')
                                    if len(left_octets) == 4 and re.fullmatch(r"\d{1,3}", right or ""):
                                        end_last = int(right)
                                        end_ip = ipaddress.ip_address("%s.%s.%s.%d" % (left_octets[0], left_octets[1], left_octets[2], end_last))
                                    elif len(left_octets) == 4 and re.fullmatch(r"\d{1,3}\.\d{1,3}", right or ""):
                                        c_str, d_str = right.split('.')
                                        if int(c_str) == int(left_octets[2]):
                                            end_ip = ipaddress.ip_address("%s.%s.%s.%d" % (left_octets[0], left_octets[1], c_str, int(d_str)))
                                        else:
                                            raise ValueError("Unsupported shorthand range")
                                    else:
                                        raise ValueError("Unsupported shorthand range")
                                assets = db.session.query(CMDBAsset).all()
                                for a in assets:
                                    if not a.ip_address:
                                        continue
                                    try:
                                        ip = ipaddress.ip_address(a.ip_address)
                                        if start_ip <= ip <= end_ip:
                                            app = None
                                            pci = None
                                            try:
                                                add = json.loads(a.additional_data) if a.additional_data else {}
                                                app = add.get('application') or add.get('application_name') or add.get('app') or add.get('service') or add.get('service_name')
                                                pci = add.get('pcidss_asset_category')
                                            except Exception:
                                                app = None
                                                pci = None
                                            matches.append({
                                                'hostname': a.hostname,
                                                'ip_address': a.ip_address,
                                                'owner': a.owner,
                                                'department': a.department,
                                                'environment': a.environment,
                                                'asset_type': a.asset_type,
                                                'operating_system': a.operating_system,
                                                'model': a.model,
                                                'manufacturer': a.manufacturer,
                                                'location': a.location,
                        							'business_unit': a.business_unit,
                                                'application': app,
                                                'pcidss_asset_category': pci
                                            })
                                    except Exception:
                                        continue
                                continue
                            except Exception:
                                pass
                    # Fallback: extract first IP from token and exact-match
                    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t_clean)
                    if ip_match:
                        ip_str = ip_match.group(0)
                        assets = db.session.query(CMDBAsset).filter(CMDBAsset.ip_address == ip_str).all()
                        for a in assets:
                            app = None
                            mapped_fields = []
                            try:
                                add = json.loads(a.additional_data) if a.additional_data else {}
                                app = add.get('application') or add.get('application_name') or add.get('app') or add.get('service') or add.get('service_name')
                                mf = add.get('__mapped_fields__')
                                if isinstance(mf, list):
                                    mapped_fields = [str(x) for x in mf]
                                pci = add.get('pcidss_asset_category')
                            except Exception:
                                app = None
                                mapped_fields = []
                                pci = None
                            matches.append({
                                'hostname': a.hostname,
                                'ip_address': a.ip_address,
                                'owner': a.owner,
                                'department': a.department,
                                'environment': a.environment,
                                'asset_type': a.asset_type,
                                'operating_system': a.operating_system,
                                'model': a.model,
                                'manufacturer': a.manufacturer,
                                'location': a.location,
                                'business_unit': a.business_unit,
                                'application': app,
                                'pcidss_asset_category': pci,
                                '__mapped_fields__': mapped_fields
                            })
                            
                        continue

                    if re.search(r"[A-Za-z]", t_clean):
                        assets = db.session.query(CMDBAsset).filter(CMDBAsset.hostname.ilike(f"%{t_clean}%")).limit(10).all()
                        if not assets:
                            assets = db.session.query(CMDBAsset).filter(CMDBAsset.additional_data.ilike(f"%{t_clean}%")).limit(10).all()
                        for a in assets:
                            app = None
                            mapped_fields = []
                            pci = None
                            try:
                                add = json.loads(a.additional_data) if a.additional_data else {}
                                app = add.get('application') or add.get('application_name') or add.get('app') or add.get('service') or add.get('service_name')
                                mf = add.get('__mapped_fields__')
                                if isinstance(mf, list):
                                    mapped_fields = [str(x) for x in mf]
                                pci = add.get('pcidss_asset_category')
                            except Exception:
                                app = None
                                mapped_fields = []
                                pci = None
                            matches.append({
                                'hostname': a.hostname,
                                'ip_address': a.ip_address,
                                'owner': a.owner,
                                'department': a.department,
                                'environment': a.environment,
                                'asset_type': a.asset_type,
                                'operating_system': a.operating_system,
                                'model': a.model,
                                'manufacturer': a.manufacturer,
                                'location': a.location,
                                'business_unit': a.business_unit,
                                'application': app,
                                'pcidss_asset_category': pci,
                                '__mapped_fields__': mapped_fields
                            })
            except Exception as e:
                logging.error(f"Error collecting CMDB matches for '{ip_field}': {str(e)}")
            # Limit to first 25 to prevent excessive payloads
            return matches[:25]

        source_cmdb_matches = _collect_cmdb_matches(self.source_ip or '')
        dest_cmdb_matches = _collect_cmdb_matches(self.dest_ip or '')

        # Compute available CMDB fields based on actual match payloads for this rule
        cmdb_available_fields = []
        try:
            fields = set()
            mapped_union = set()
            base_fields = [
                'hostname','ip_address','owner','department','asset_type','operating_system','location','environment',
                'status','manufacturer','model','serial_number','asset_tag','application_name','application','pcidss_asset_category'
            ]
            for m in (source_cmdb_matches or []):
                for k, v in (m or {}).items():
                    if v not in [None, '', 'None']:
                        fields.add(k)
                mf = m.get('__mapped_fields__')
                if isinstance(mf, list):
                    for x in mf:
                        mapped_union.add(str(x))
            for m in (dest_cmdb_matches or []):
                for k, v in (m or {}).items():
                    if v not in [None, '', 'None']:
                        fields.add(k)
                mf = m.get('__mapped_fields__')
                if isinstance(mf, list):
                    for x in mf:
                        mapped_union.add(str(x))
            # Include enriched normalized fields if present
            for f in ['source_hostname','source_owner','source_department','source_environment','dest_hostname','dest_owner','dest_department','dest_environment']:
                v = getattr(self, f)
                if v not in [None, '', 'None']:
                    fields.add(f.replace('source_','').replace('dest_',''))
            computed = [f for f in fields if f in base_fields or True]
            cmdb_available_fields = sorted(list(set(computed).intersection(mapped_union))) if mapped_union else sorted(list(set(computed)))
        except Exception:
            cmdb_available_fields = []

        return {
            'id': self.id,
            'raw_rule_id': self.raw_rule_id,
            'source_file': self.source_file,
            'rule_name': self.rule_name or (raw_result.rule_name if raw_result else None),
            'rule_type': self.rule_type,
            'action': self.action,
            'is_disabled': self.is_disabled,
            'protocol': self.protocol,
            'source_zone': self.source_zone,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'source_hostname': self.source_hostname,
            'source_owner': self.source_owner,
            'source_department': self.source_department,
            'source_environment': self.source_environment,
            'source_vlan_id': self.source_vlan_id,
            'source_vlan_name': self.source_vlan_name,
            'source_subnet': self.source_subnet,
            'source_location': self.source_location,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'dest_zone': self.dest_zone,
            'dest_hostname': self.dest_hostname,
            'dest_owner': self.dest_owner,
            'dest_department': self.dest_department,
            'dest_environment': self.dest_environment,
            'dest_vlan_id': self.dest_vlan_id,
            'dest_vlan_name': self.dest_vlan_name,
            'dest_subnet': self.dest_subnet,
            'dest_location': self.dest_location,
            'source_cmdb_matches': source_cmdb_matches,
            'dest_cmdb_matches': dest_cmdb_matches,
            'cmdb_available_fields': cmdb_available_fields,
            'service_name': self.service_name,
            'service_port': self.service_port,
            'service_protocol': self.service_protocol,
            'hit_count': self.hit_count,
            'application': self.application,
            'risk_level': self.risk_level,
            'compliance_status': self.compliance_status,
            'formatted_compliance_status': formatted_compliance_status,
            'compliance_reasons': compliance_reasons[:10] if compliance_reasons else [],
            'compliance_profile_info': {
                'profile_name': compliance_profile_info.get('profile_name') if compliance_profile_info else None,
                'compliance_framework': compliance_profile_info.get('compliance_framework') if compliance_profile_info else None,
                'overall_status': compliance_profile_info.get('overall_status') if compliance_profile_info else None
            } if compliance_profile_info else None,
            'review_status': self.review_status,
            'notes': self.notes,
            'owner_approval': self.owner_approval,
            'is_deleted': self.is_deleted,
            'raw_text': raw_text,
            'rule_text': raw_result.rule_text if raw_result else None,
            # FIX: avoid overriding normalized rule_name with raw_result.rule_name
            'raw_rule_name': raw_result.rule_name if raw_result else None,
            'raw_data': raw_data,
            'custom_fields_data': json.loads(self.custom_fields_data) if self.custom_fields_data else {},
            'normalization_date': self.normalization_date.isoformat() if self.normalization_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def to_summary_dict(self):
        """Lightweight serializer for list views without expensive CMDB/compliance joins."""
        # Try to get raw rule name via relationship without deep joins
        try:
            raw_rule_name = self.raw_rule.rule_name if self.raw_rule else None
        except Exception:
            raw_rule_name = None
        return {
            'id': self.id,
            'raw_rule_id': self.raw_rule_id,
            'source_file': self.source_file,
            'rule_name': self.rule_name,
            'raw_rule_name': raw_rule_name,
            'rule_type': self.rule_type,
            'action': self.action,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'source_ip_with_zone': self.source_ip_with_zone,
            'source_zone': self.source_zone,
            'source_vlan_id': self.source_vlan_id,
            'source_vlan_name': self.source_vlan_name,
            'source_subnet': self.source_subnet,
            'source_location': self.source_location,
            'dest_ip': self.dest_ip,
            'dest_ip_with_zone': self.dest_ip_with_zone,
            'dest_zone': self.dest_zone,
            'dest_port': self.dest_port,
            'dest_vlan_id': self.dest_vlan_id,
            'dest_vlan_name': self.dest_vlan_name,
            'dest_subnet': self.dest_subnet,
            'dest_location': self.dest_location,
            'service_name': self.service_name,
            'hit_count': self.hit_count,
            'risk_level': self.risk_level,
            'compliance_status': self.compliance_status,
            'is_deleted': self.is_deleted,
            'custom_fields_data': json.loads(self.custom_fields_data) if self.custom_fields_data else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# Add an UploadHistory model to track file uploads
class UploadHistory(db.Model):
    """Tracks file upload history and processing status"""
    __tablename__ = 'upload_history'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # firewall, cmdb, vlan
    file_size = db.Column(db.Integer)
    
    # Processing status
    status = db.Column(db.String(50), default='uploaded')  # uploaded, processing, completed, failed
    records_processed = db.Column(db.Integer, default=0)
    errors_count = db.Column(db.Integer, default=0)
    error_details = db.Column(db.Text)  # JSON string with error details
    
    # Metadata
    uploaded_by = db.Column(db.String(100))  # Future: user identification
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        error_details = []
        if self.error_details:
            try:
                error_details = json.loads(self.error_details)
            except json.JSONDecodeError:
                pass
        
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'status': self.status,
            'records_processed': self.records_processed,
            'errors_count': self.errors_count,
            'error_details': error_details,
            'uploaded_by': self.uploaded_by,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None
        }


class ComplianceRule(db.Model):
    """
    Stores individual compliance checks that can be applied to normalized rules.
    Each rule defines a specific check with field, operator, and expected value.
    """
    __tablename__ = 'compliance_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # The field in NormalizedRule to check
    field_to_check = db.Column(db.String(100), nullable=False)  # e.g., "service_port", "action", "protocol"
    
    # Comparison operator
    operator = db.Column(db.String(50), nullable=False)  # in_list, not_in_list, equals, not_equals, regex_match, contains
    
    logic = db.Column(db.String(10)) # AND, OR, NOT
    
    # Expected value(s) - stored as string, parsed based on operator
    value = db.Column(db.Text, nullable=False)  # e.g., "TCP/21,TCP/23,TCP/80" or "deny" or "^192\.168\."
    
    # Severity of non-compliance
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    
    # Rule status
    is_active = db.Column(db.Boolean, default=True)
    
    # Metadata
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'description': self.description,
            'field_to_check': self.field_to_check,
            'operator': self.operator,
            'logic': self.logic,
            'value': self.value,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ReviewProfile(db.Model):
    """
    Templates that group multiple compliance rules together.
    Examples: "PCI Compliance Check", "SOX Audit", "Security Baseline"
    """
    __tablename__ = 'review_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    
    # Profile metadata
    compliance_framework = db.Column(db.String(100))  # e.g., "PCI-DSS", "SOX", "NIST"
    version = db.Column(db.String(50))  # e.g., "v3.2.1"
    
    # Profile status
    is_active = db.Column(db.Boolean, default=True)
    
    # Metadata
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'profile_name': self.profile_name,
            'description': self.description,
            'compliance_framework': self.compliance_framework,
            'version': self.version,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'rule_count': len(self.rules) if hasattr(self, 'rules') else 0
        }


class ProfileRuleLink(db.Model):
    """
    Many-to-many relationship between ReviewProfile and ComplianceRule.
    Allows rules to be reused across multiple profiles.
    """
    __tablename__ = 'profile_rule_link'
    
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('review_profiles.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('compliance_rules.id'), nullable=False)
    
    # Optional: rule-specific settings within this profile
    weight = db.Column(db.Float, default=1.0)  # Importance weight for this rule in this profile
    is_mandatory = db.Column(db.Boolean, default=True)  # Whether this rule is mandatory for compliance
    
    # Metadata
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.String(100))
    
    # Relationships
    profile = db.relationship('ReviewProfile', backref=db.backref('rule_links', lazy=True, cascade='all, delete-orphan'))
    rule = db.relationship('ComplianceRule', backref=db.backref('profile_links', lazy=True), overlaps="profiles,rules")
    
    # Unique constraint to prevent duplicate links
    __table_args__ = (db.UniqueConstraint('profile_id', 'rule_id', name='unique_profile_rule'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'profile_id': self.profile_id,
            'rule_id': self.rule_id,
            'weight': self.weight,
            'is_mandatory': self.is_mandatory,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'added_by': self.added_by,
            'rule_name': self.rule.rule_name if self.rule else None,
            'rule_description': self.rule.description if self.rule else None,
            'rule_severity': self.rule.severity if self.rule else None
        }


class ReviewResult(db.Model):
    """Stores results of compliance checks for each normalized rule"""
    __tablename__ = 'review_results'
    
    id = db.Column(db.Integer, primary_key=True)
    normalized_rule_id = db.Column(db.Integer, db.ForeignKey('normalized_rules.id'), nullable=False)
    compliance_rule_id = db.Column(db.Integer, db.ForeignKey('compliance_rules.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('review_profiles.id'), nullable=False)
    
    # Review execution details
    review_session_id = db.Column(db.String(100), nullable=False)  # UUID for grouping results from same review run
    
    # Compliance check result
    status = db.Column(db.String(20), nullable=False)  # compliant, non_compliant
    failed_checks = db.Column(db.Text)  # JSON array of specific check failures
    severity = db.Column(db.String(20))  # Critical, High, Medium, Low (from compliance rule)
    
    # Additional context
    notes = db.Column(db.Text)  # Additional notes about the finding
    
    # Metadata
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    normalized_rule = db.relationship('NormalizedRule', backref=db.backref('review_results', lazy=True))
    compliance_rule = db.relationship('ComplianceRule', backref=db.backref('review_results', lazy=True))
    profile = db.relationship('ReviewProfile', backref=db.backref('review_results', lazy=True))
    
    # Ensure unique combination of normalized_rule, compliance_rule, and review_session
    __table_args__ = (
        db.UniqueConstraint('normalized_rule_id', 'compliance_rule_id', 'review_session_id', 
                          name='unique_rule_check_session'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'normalized_rule_id': self.normalized_rule_id,
            'compliance_rule_id': self.compliance_rule_id,
            'profile_id': self.profile_id,
            'review_session_id': self.review_session_id,
            'status': self.status,
            'failed_checks': json.loads(self.failed_checks) if self.failed_checks else [],
            'severity': self.severity,
            'notes': self.notes,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


# Add relationship to ReviewProfile for easier access to rules
ReviewProfile.rules = db.relationship('ComplianceRule', secondary='profile_rule_link', 
                                     backref=db.backref('profiles', lazy=True), lazy=True, overlaps="profile_links,rule")


class ExportProfile(db.Model):
    __tablename__ = 'export_profiles'

    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    format = db.Column(db.String(20), nullable=False)  # pdf, excel, csv
    include_compliant = db.Column(db.Boolean, default=True)
    group_by = db.Column(db.String(50))
    selected_fields = db.Column(db.Text)  # JSON array
    include_sections = db.Column(db.Text)  # JSON array
    filters = db.Column(db.Text)  # JSON object
    charts = db.Column(db.Text)  # JSON object
    tiles = db.Column(db.Text)  # JSON object
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        import json
        def _load(text, default):
            try:
                return json.loads(text) if text else default
            except Exception:
                return default
        return {
            'id': self.id,
            'profile_name': self.profile_name,
            'description': self.description,
            'format': self.format,
            'include_compliant': self.include_compliant,
            'group_by': self.group_by,
            'selected_fields': _load(self.selected_fields, []),
            'include_sections': _load(self.include_sections, []),
            'filters': _load(self.filters, {}),
            'charts': _load(self.charts, {}),
            'tiles': _load(self.tiles, {}),
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class CustomFieldModel(db.Model):
    __tablename__ = 'custom_fields'
    id = db.Column(db.Integer, primary_key=True)
    field_name = db.Column(db.String(100), nullable=False, unique=True)
    display_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    field_type = db.Column(db.String(50), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    is_mandatory = db.Column(db.Boolean, default=False)
    is_important = db.Column(db.Boolean, default=False)
    default_value = db.Column(db.String(255))
    validation_rules = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'field_name': self.field_name,
            'display_name': self.display_name,
            'description': self.description,
            'field_type': self.field_type,
            'file_type': self.file_type,
            'is_mandatory': self.is_mandatory,
            'is_important': self.is_important,
            'default_value': self.default_value,
            'validation_rules': self.validation_rules,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

class CustomRuleModel(db.Model):
    __tablename__ = 'custom_rules'
    id = db.Column(db.Integer, primary_key=True)
    field_id = db.Column(db.Integer, db.ForeignKey('custom_fields.id'), nullable=False)
    rule_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    condition_type = db.Column(db.String(50), nullable=False)
    condition_value = db.Column(db.Text, nullable=False)
    action = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    field = db.relationship('CustomFieldModel', backref=db.backref('rules', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'field_id': self.field_id,
            'rule_name': self.rule_name,
            'description': self.description,
            'condition_type': self.condition_type,
            'condition_value': self.condition_value,
            'action': self.action,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
