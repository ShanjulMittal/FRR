import logging
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from sqlalchemy import or_, and_, text
import json
import csv
import io
import re
import uuid
import os
from datetime import datetime, timedelta

from models import db, ComplianceRule, ReviewResult, ReviewProfile, NormalizedRule, CMDBAsset, VLANNetwork, RawFirewallRule, ObjectGroup, ServicePortMapping, CustomFieldModel, CustomRuleModel, ProfileRuleLink, ObjectGroupMember
from compliance_engine import ComplianceEngine
from review_engine import run_review_process
from parsers.parser_factory import parser_factory
from export_service import generate_excel_export
from object_group_scanner import scan_for_object_groups
from iana_import import import_iana_service_mappings


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _get_uploads_dir():
    uploads_dir = os.getenv('UPLOADS_DIR')
    if not uploads_dir:
        uploads_dir = '/data/uploads' if os.path.isdir('/data') else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    return uploads_dir


app = Flask(__name__)
CORS(app)

# Database configuration
db_url = os.getenv('DATABASE_URL')
if not db_url:
    db_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall_review.db')
    db_url = f"sqlite:///{db_file_path}"
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    try:
        db.create_all()
        cols = db.session.execute(text("PRAGMA table_info(compliance_rules)")).fetchall()
        col_names = {row[1] for row in cols}
        if 'logic' not in col_names:
            db.session.execute("ALTER TABLE compliance_rules ADD COLUMN logic VARCHAR(10)")
            db.session.commit()
        try:
            defaults = [
                {'field_name':'rule_name','display_name':'Rule Name','description':'Rule name','field_type':'text','file_type':'firewall','is_mandatory':False,'is_important':True,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'},
                {'field_name':'sourcezone','display_name':'Source Zone','description':'Source zone','field_type':'text','file_type':'firewall','is_mandatory':False,'is_important':True,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'},
                {'field_name':'destinationzone','display_name':'Destination Zone','description':'Destination zone','field_type':'text','file_type':'firewall','is_mandatory':False,'is_important':True,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'},
                {'field_name':'service_count','display_name':'Service Count','description':'Number of services','field_type':'number','file_type':'firewall','is_mandatory':False,'is_important':False,'default_value':'0','validation_rules':'min:0','is_active':True,'created_by':'system'},
                {'field_name':'hit_count','display_name':'Hit Count','description':'Total hits','field_type':'number','file_type':'firewall','is_mandatory':False,'is_important':False,'default_value':'0','validation_rules':'min:0','is_active':True,'created_by':'system'},
                {'field_name':'application_name','display_name':'Application Name','description':'Application name','field_type':'text','file_type':'cmdb','is_mandatory':False,'is_important':True,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'},
                {'field_name':'pcidss_asset_category','display_name':'PCI DSS Category','description':'PCI DSS asset category','field_type':'text','file_type':'cmdb','is_mandatory':False,'is_important':False,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'},
                {'field_name':'environment','display_name':'Environment','description':'Environment','field_type':'text','file_type':'cmdb','is_mandatory':False,'is_important':False,'default_value':'','validation_rules':'','is_active':True,'created_by':'system'}
            ]
            for d in defaults:
                from sqlalchemy import select
                exists = db.session.execute(select(CustomFieldModel).where(CustomFieldModel.field_name == d['field_name'])).first()
                if not exists:
                    f = CustomFieldModel(**d)
                    db.session.add(f)
            db.session.commit()
        except Exception as se:
            logger.warning(f"Custom fields seed failed: {se}")
        try:
            existing = ComplianceRule.query.filter(ComplianceRule.rule_name == 'PCIDSS zone violation').first()
            if not existing:
                rule = ComplianceRule(
                    rule_name='PCIDSS zone violation',
                    description='Non-compliant when action is allow/permit and source CMDB category is A while destination is C, or vice versa',
                    field_to_check='action',
                    operator='cmdb_category_violation',
                    logic=None,
                    value='A<->C',
                    severity='High',
                    is_active=True,
                    created_by='system'
                )
                db.session.add(rule)
                db.session.commit()
                profiles = ReviewProfile.query.all()
                for p in profiles:
                    link_exists = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id, ProfileRuleLink.rule_id == rule.id).first()
                    if not link_exists:
                        db.session.add(ProfileRuleLink(profile_id=p.id, rule_id=rule.id, weight=1.0, is_mandatory=True, added_by='system'))
                db.session.commit()
        except Exception as e:
            logger.warning(f"PCIDSS zone violation seed failed: {e}")
        try:
            existing = ComplianceRule.query.filter(ComplianceRule.rule_name == 'Business Documentation - Change reference').first()
            
            # Composite logic: Violation if (Action NOT contains "disabled") AND (Rule Name NOT matches reference)
            composite_logic = {
                "logic": "AND",
                "conditions": [
                    {
                        "field": "action",
                        "operator": "not_contains",
                        "value": "disabled"
                    },
                    {
                        "field": "rule_name",
                        "operator": "not_regex_match",
                        "value": r"(CHG|CTASK|CMR|AU-C|ECMR|CR|18|19|17|16|15|14|13|12)[-_ ]?\d+"
                    }
                ]
            }
            composite_value = json.dumps(composite_logic)

            if not existing:
                rule = ComplianceRule(
                    rule_name='Business Documentation - Change reference',
                    description='Rule must contain a valid Change reference (CHG/CTASK/CMR/AU-C/ECMR/CR or starting with 12-19) OR be disabled',
                    field_to_check='rule_name',
                    operator='composite',
                    logic=None,
                    value=composite_value,
                    severity='Medium',
                    is_active=True,
                    created_by='system'
                )
                db.session.add(rule)
                db.session.commit()
                profiles = ReviewProfile.query.all()
                for p in profiles:
                    link_exists = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id, ProfileRuleLink.rule_id == rule.id).first()
                    if not link_exists:
                        db.session.add(ProfileRuleLink(profile_id=p.id, rule_id=rule.id, weight=1.0, is_mandatory=True, added_by='system'))
                db.session.commit()
            else:
                # Ensure operator/value are correct for existing rule
                changed = False
                if existing.operator != 'composite':
                    existing.operator = 'composite'
                    changed = True
                if existing.value != composite_value:
                    existing.value = composite_value
                    changed = True
                if existing.description != 'Rule must contain a valid Change reference (CHG/CTASK/CMR/AU-C/ECMR/CR or starting with 12-19) OR be disabled':
                    existing.description = 'Rule must contain a valid Change reference (CHG/CTASK/CMR/AU-C/ECMR/CR or starting with 12-19) OR be disabled'
                    changed = True
                if changed:
                    db.session.commit()
        except Exception as e:
            logger.warning(f"Business Documentation rule seed failed: {e}")
        try:
            rule_name = 'Specific Source/Dest with Any Service'
            existing = ComplianceRule.query.filter(ComplianceRule.rule_name == rule_name).first()
            if not existing:
                logic_dict = {
                    "logic": "AND",
                    "conditions": [
                        {"field": "action", "operator": "equals", "value": "permit"},
                        {"logic": "AND", "conditions": [
                            {"field": "source_ip", "operator": "not_equals", "value": "any"},
                            {"field": "source_ip", "operator": "is_not_empty", "value": ""}
                        ]},
                        {"logic": "AND", "conditions": [
                            {"field": "dest_ip", "operator": "not_equals", "value": "any"},
                            {"field": "dest_ip", "operator": "is_not_empty", "value": ""}
                        ]},
                        {"logic": "AND", "conditions": [
                            {"logic": "OR", "conditions": [
                                {"field": "service_port", "operator": "equals", "value": "any"},
                                {"field": "service_port", "operator": "regex_match", "value": r"^(\*|any|all|0\s*-\s*65535|1\s*-\s*65535)$"},
                                {"field": "dest_port", "operator": "equals", "value": "any"},
                                {"field": "dest_port", "operator": "regex_match", "value": r"^(\*|any|all|0\s*-\s*65535|1\s*-\s*65535)$"},
                                {"field": "service_name", "operator": "equals", "value": "any"},
                                {"field": "service_name", "operator": "regex_match", "value": r"^(\*|any|all)$"},
                                {"field": "protocol", "operator": "in_list", "value": "any,ip,*"},
                                {"logic": "AND", "conditions": [
                                    {"field": "service_port", "operator": "is_empty", "value": ""},
                                    {"field": "dest_port", "operator": "is_empty", "value": ""},
                                    {"field": "service_name", "operator": "is_empty", "value": ""}
                                ]}
                            ]},
                            {"logic": "OR", "conditions": [
                                {"field": "application", "operator": "equals", "value": "any"},
                                {"field": "application", "operator": "regex_match", "value": r"^(\*|any|all)$"},
                                {"field": "application", "operator": "is_empty", "value": ""}
                            ]}
                        ]}
                    ]
                }
                rule = ComplianceRule(
                    rule_name=rule_name,
                    description='Non-compliant if Source and Destination are specific but Service/Application is ANY',
                    field_to_check='multiple',
                    operator='composite',
                    logic=None,
                    value=json.dumps(logic_dict),
                    severity='High',
                    is_active=True,
                    created_by='system'
                )
                db.session.add(rule)
                db.session.commit()
                profiles = ReviewProfile.query.all()
                for p in profiles:
                    link_exists = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id, ProfileRuleLink.rule_id == rule.id).first()
                    if not link_exists:
                        db.session.add(ProfileRuleLink(profile_id=p.id, rule_id=rule.id, weight=1.0, is_mandatory=True, added_by='system'))
                db.session.commit()
        except Exception as e:
            logger.warning(f"{rule_name} seed failed: {e}")
        try:
            cols_raw = db.session.execute(text("PRAGMA table_info(raw_firewall_rules)")).fetchall()
            raw_cols = {row[1] for row in cols_raw}
            if 'hit_count' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN hit_count INTEGER"))
            if 'source_vlan_id' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN source_vlan_id INTEGER"))
            if 'source_vlan_name' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN source_vlan_name VARCHAR(255)"))
            if 'dest_vlan_id' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN dest_vlan_id INTEGER"))
            if 'dest_vlan_name' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN dest_vlan_name VARCHAR(255)"))
            if 'is_disabled' not in raw_cols:
                db.session.execute(text("ALTER TABLE raw_firewall_rules ADD COLUMN is_disabled INTEGER DEFAULT 0"))
            db.session.commit()
        except Exception as e:
            logger.warning(f"Schema check failed for raw_firewall_rules: {e}")
        try:
            cols_norm = db.session.execute(text("PRAGMA table_info(normalized_rules)")).fetchall()
            norm_cols = {row[1] for row in cols_norm}
            norm_column_defs = {
                'hit_count': "INTEGER",
                'source_vlan_id': "INTEGER",
                'source_vlan_name': "VARCHAR(255)",
                'dest_vlan_id': "INTEGER",
                'dest_vlan_name': "VARCHAR(255)",
                'source_subnet': "VARCHAR(50)",
                'dest_subnet': "VARCHAR(50)",
                'is_disabled': "INTEGER DEFAULT 0",
            }
            for col, ddl in norm_column_defs.items():
                if col not in norm_cols:
                    db.session.execute(text(f"ALTER TABLE normalized_rules ADD COLUMN {col} {ddl}"))
            db.session.commit()
        except Exception as e:
            logger.warning(f"Schema check failed for normalized_rules: {e}")
        try:
            if ReviewProfile.query.count() == 0:
                pci = ReviewProfile(profile_name='PCI DSS 4.0.1 Template', compliance_framework='PCI-DSS', version='4.0.1', is_active=True, created_by='system')
                iso = ReviewProfile(profile_name='ISO 27001 Baseline', compliance_framework='ISO27001', version='2013', is_active=True, created_by='system')
                db.session.add(pci)
                db.session.add(iso)
                db.session.commit()
                sample_rules = ComplianceRule.query.limit(10).all()
                for r in sample_rules:
                    for prof in [pci, iso]:
                        exists = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == prof.id, ProfileRuleLink.rule_id == r.id).first()
                        if not exists:
                            db.session.add(ProfileRuleLink(profile_id=prof.id, rule_id=r.id, weight=1.0, is_mandatory=True, added_by='system'))
                db.session.commit()
        except Exception as e:
            logger.warning(f"Default profile seed failed: {e}")
    except Exception as e:
        logger.warning(f"Database init failed: {e}")


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200


@app.route('/api/compliance-rules', methods=['GET'])
def get_compliance_rules():
    """Get compliance rules with pagination and optional search by name/description"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search_query = request.args.get('search', '', type=str).strip()

        query = ComplianceRule.query

        if search_query:
            like = f"%{search_query}%"
            query = query.filter(or_(
                ComplianceRule.rule_name.ilike(like),
                ComplianceRule.description.ilike(like)
            ))

        pagination = query.order_by(ComplianceRule.id.asc()).paginate(page=page, per_page=per_page, error_out=False)
        rules = pagination.items

        return jsonify({
            'rules': [r.to_dict() for r in rules],
            'total_items': pagination.total,
            'total_pages': pagination.pages,
            'current_page': page
        })
    except Exception as e:
        logger.error(f"Error getting compliance rules: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance-rules/<int:rule_id>', methods=['GET'])
def get_compliance_rule(rule_id):
    try:
        rule = ComplianceRule.query.get_or_404(rule_id)
        return jsonify(rule.to_dict())
    except Exception as e:
        logger.error(f"Error getting compliance rule {rule_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance-rules', methods=['POST'])
def create_compliance_rule():
    try:
        data = request.get_json() or {}
        operator = data.get('operator')
        value = data.get('value')
        field_to_check = data.get('field_to_check')
        if operator == 'composite' or field_to_check == '__composite__':
            operator = 'composite'
            # store as string JSON
            value = value if isinstance(value, str) else json.dumps(value or {'logic':'AND','conditions':[]})
            field_to_check = 'composite'
        rule = ComplianceRule(
            rule_name=data.get('rule_name'),
            description=data.get('description'),
            field_to_check=field_to_check,
            operator=operator,
            logic=data.get('logic'),
            value=value,
            severity=data.get('severity') or 'Medium',
            is_active=bool(data.get('is_active', True)),
            created_by=data.get('created_by') or 'admin'
        )
        db.session.add(rule)
        db.session.commit()
        return jsonify({'success': True, 'rule': rule.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating compliance rule: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/compliance-rules/<int:rule_id>', methods=['PUT'])
def update_compliance_rule(rule_id):
    try:
        data = request.get_json() or {}
        rule = ComplianceRule.query.get_or_404(rule_id)
        operator = data.get('operator', rule.operator)
        value = data.get('value', rule.value)
        field_to_check = data.get('field_to_check', rule.field_to_check)
        if operator == 'composite' or field_to_check == '__composite__':
            operator = 'composite'
            value = value if isinstance(value, str) else json.dumps(value or {'logic':'AND','conditions':[]})
            field_to_check = 'composite'
        for k, v in {
            'rule_name': data.get('rule_name', rule.rule_name),
            'description': data.get('description', rule.description),
            'field_to_check': field_to_check,
            'operator': operator,
            'logic': data.get('logic', rule.logic),
            'value': value,
            'severity': data.get('severity', rule.severity),
            'is_active': bool(data.get('is_active', rule.is_active)),
            'created_by': data.get('created_by', rule.created_by)
        }.items():
            setattr(rule, k, v)
        db.session.commit()
        return jsonify({'success': True, 'rule': rule.to_dict()})
    except Exception as e:
        logger.error(f"Error updating compliance rule {rule_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/compliance-rules/<int:rule_id>', methods=['DELETE'])
def delete_compliance_rule(rule_id):
    try:
        rule = ComplianceRule.query.get_or_404(rule_id)
        db.session.delete(rule)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting compliance rule {rule_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/compliance/fields', methods=['GET'])
def get_compliance_fields():
    """Return available fields for building compliance rules"""
    try:
        fields = [
            {'name': 'action', 'description': 'Action (permit/deny)'},
            {'name': 'protocol', 'description': 'Protocol (tcp/udp/icmp/ip)'},
            {'name': 'source_ip', 'description': 'Source IP'},
            {'name': 'dest_ip', 'description': 'Destination IP'},
            {'name': 'service_port', 'description': 'Service Port'},
            {'name': 'source_zone', 'description': 'Source Zone'},
            {'name': 'dest_zone', 'description': 'Destination Zone'},
        ]
        return jsonify({'fields': fields})
    except Exception as e:
        logger.error(f"Error getting compliance fields: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/compliance/operators', methods=['GET'])
def get_compliance_operators():
    """Return available operators for compliance rules"""
    try:
        operators = [
            {'name': 'equals', 'label': 'Equals'},
            {'name': 'not_equals', 'label': 'Not Equals'},
            {'name': 'contains', 'label': 'Contains'},
            {'name': 'regex_match', 'label': 'Regex Match'},
            {'name': 'in_list', 'label': 'In List'},
            {'name': 'not_in_list', 'label': 'Not In List'},
            {'name': 'cmdb_category_violation', 'label': 'CMDB PCI DSS Category Violation'},
        ]
        return jsonify({'operators': operators})
    except Exception as e:
        logger.error(f"Error getting operators: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/object-groups/bulk-delete', methods=['DELETE'])
def bulk_delete_object_groups():
    try:
        data = request.get_json() or {}
        if data.get('delete_all'):
            # Delete all members first (cascade usually handles this, but being explicit is safe)
            db.session.query(ObjectGroupMember).delete()
            db.session.query(ObjectGroup).delete()
            db.session.commit()
            return jsonify({'success': True})
        
        ids = data.get('ids', [])
        if ids:
            db.session.query(ObjectGroupMember).filter(ObjectGroupMember.object_group_id.in_(ids)).delete()
            db.session.query(ObjectGroup).filter(ObjectGroup.id.in_(ids)).delete()
            db.session.commit()
            return jsonify({'success': True})
            
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting object groups: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/scan-object-groups', methods=['POST'])
def scan_object_groups():
    try:
        data = request.get_json() or {}
        source_file = data.get('source_file')
        # Use the dedicated scanner that works from raw_firewall_rules,
        # which are populated as part of the import/normalization pipeline.
        results = scan_for_object_groups(source_file=source_file)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error scanning object groups: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/import-templates/vlan-object-group', methods=['GET'])
def get_vlan_object_group_template():
    try:
        # Create a CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        headers = ['record_type', 'name', 'description', 'vlan_id', 'subnet', 'gateway', 'group_type', 'protocol', 'members']
        writer.writerow(headers)
        
        # Example row for VLAN
        writer.writerow(['VLAN', 'Example VLAN', 'This is a VLAN', '100', '192.168.1.0/24', '192.168.1.1', '', '', ''])
        
        # Example row for Object Group
        writer.writerow(['OBJECT_GROUP', 'Example Group', 'This is an Object Group', '', '', '', 'network', 'ip', '10.0.0.1, 10.0.0.2'])
        
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='vlan_object_group_import_template.csv'
        )
    except Exception as e:
        logger.error(f"Error generating template: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance-rules/seed/pcidss-zone-violation', methods=['POST'])
def seed_pcidss_zone_violation():
    try:
        existing = ComplianceRule.query.filter(ComplianceRule.rule_name == 'PCIDSS zone violation').first()
        if not existing:
            rule = ComplianceRule(
                rule_name='PCIDSS zone violation',
                description='Non-compliant when action is allow/permit and source CMDB PCI DSS category is A while destination is C, or vice versa',
                field_to_check='action',
                operator='cmdb_category_violation',
                logic=None,
                value='A<->C',
                severity='High',
                is_active=True,
                created_by='system'
            )
            db.session.add(rule)
            db.session.commit()
            target_rule = rule
        else:
            # Update operator/description/metadata to correct logic
            existing.operator = 'cmdb_category_violation'
            existing.field_to_check = 'action'
            existing.logic = None
            existing.value = 'A<->C'
            existing.severity = 'High'
            existing.description = 'Non-compliant when action is allow/permit and source CMDB PCI DSS category is A while destination is C, or vice versa'
            existing.is_active = True
            db.session.commit()
            target_rule = existing
        # Link to all profiles if missing
        profiles = ReviewProfile.query.all()
        linked = 0
        for p in profiles:
            exists_link = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id, ProfileRuleLink.rule_id == target_rule.id).first()
            if not exists_link:
                db.session.add(ProfileRuleLink(profile_id=p.id, rule_id=target_rule.id, weight=1.0, is_mandatory=True, added_by='system'))
                linked += 1
        if linked:
            db.session.commit()
        return jsonify({'success': True, 'rule': target_rule.to_dict(), 'linked_profiles_added': linked})
    except Exception as e:
        logger.error(f"Error seeding PCIDSS zone violation rule: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/compliance/evaluate/rule/<int:nr_id>', methods=['GET'])
def evaluate_pcidss_zone_violation_for_rule(nr_id: int):
    try:
        nr = NormalizedRule.query.get_or_404(nr_id)
        def norm_cat(v: str) -> str:
            s = (v or '').strip().upper()
            if s.startswith('CATEGORY '):
                s = s.split(' ', 1)[1]
            m = re.match(r'^CAT\s*([A-Z])$', s)
            if m:
                s = m.group(1)
            return s
        # Prefer categories from details
        try:
            d = nr.to_dict()
            src_cats = list({norm_cat(m.get('pcidss_asset_category')) for m in (d.get('source_cmdb_matches') or []) if m.get('pcidss_asset_category')})
            dst_cats = list({norm_cat(m.get('pcidss_asset_category')) for m in (d.get('dest_cmdb_matches') or []) if m.get('pcidss_asset_category')})
        except Exception:
            src_cats, dst_cats = [], []
        action_raw = str(getattr(nr, 'action', '') or '').strip().lower()
        action_tokens = [t.strip() for t in re.split(r"[;\,\|\s]+", action_raw) if t.strip()]
        deny_block = any(t in ('deny','block','drop') for t in action_tokens)
        allow_permit = any(t in ('allow','permit') for t in action_tokens) if action_tokens else (action_raw in ('allow','permit'))
        violation = (('A' in src_cats and 'C' in dst_cats) or ('C' in src_cats and 'A' in dst_cats)) and allow_permit and not deny_block
        return jsonify({
            'normalized_rule_id': nr_id,
            'source_categories': src_cats,
            'dest_categories': dst_cats,
            'action': action_raw,
            'action_tokens': action_tokens,
            'violation': violation,
            'compliant': (not violation)
        })
    except Exception as e:
        logger.error(f"Diagnostic evaluation failed for NR {nr_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    try:
        total_rules = db.session.query(NormalizedRule).count()
        total_assets = db.session.query(CMDBAsset).count()
        total_vlans = db.session.query(VLANNetwork).count()
        compliance_score = 0
        return jsonify({
            'total_rules': total_rules,
            'total_assets': total_assets,
            'total_vlans': total_vlans,
            'compliance_score': compliance_score
        })
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/reviews/sessions', methods=['GET'])
def get_review_sessions():
    try:
        from sqlalchemy import text
        q = text(
            """
            SELECT rr.review_session_id AS review_session_id,
                   MAX(rr.checked_at) AS started_at,
                   COUNT(*) AS total_checks,
                   COALESCE(rp.profile_name, '') AS profile_name
            FROM review_results rr
            LEFT JOIN review_profiles rp ON rr.profile_id = rp.id
            GROUP BY rr.review_session_id
            ORDER BY started_at DESC
            """
        )
        rows = db.session.execute(q).fetchall()
        data = [
            {
                'review_session_id': row.review_session_id,
                'profile_name': row.profile_name,
                'started_at': (row.started_at.isoformat() if hasattr(row.started_at, 'isoformat') else (str(row.started_at) if row.started_at else None)),
                'total_checks': row.total_checks,
            }
            for row in rows
        ]
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        logger.error(f"Error getting review sessions: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/reviews/summary/<string:session_id>', methods=['GET'])
def get_review_summary(session_id):
    try:
        from review_engine import get_review_summary as build_summary
        summary = build_summary(session_id)
        if summary.get('success'):
            return jsonify({'success': True, 'data': summary})
        else:
            return jsonify({'success': False, 'error': summary.get('error', 'No results')})
    except Exception as e:
        logger.error(f"Error getting review summary for {session_id}: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/rules', methods=['GET'])
def get_raw_rules():
    """List raw firewall rules with pagination, sorting, and basic filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        sort_by = request.args.get('sort_by', 'id', type=str)
        sort_order = request.args.get('sort_order', 'desc', type=str)

        # Base query
        query = RawFirewallRule.query

        # Filters
        source_file = request.args.get('source_file')
        rule_type = request.args.get('rule_type')
        action = request.args.get('action')
        protocol = request.args.get('protocol')
        search = request.args.get('search', '', type=str).strip()
        search_scope = request.args.get('search_scope', 'all', type=str)
        search_field = request.args.get('search_fields', '', type=str)

        if source_file:
            query = query.filter(RawFirewallRule.source_file == source_file)
        if rule_type:
            query = query.filter(RawFirewallRule.rule_type == rule_type)
        if action:
            query = query.filter(RawFirewallRule.action == action)
        if protocol:
            query = query.filter(RawFirewallRule.protocol == protocol)

        if search:
            like = f"%{search}%"
            fields = []
            # Scope-based defaults
            if search_scope == 'ip':
                fields = [RawFirewallRule.source, RawFirewallRule.destination]
            elif search_scope == 'port':
                fields = [RawFirewallRule.source_port, RawFirewallRule.dest_port]
            else:
                fields = [
                    RawFirewallRule.rule_name,
                    RawFirewallRule.rule_text,
                    RawFirewallRule.raw_text,
                    RawFirewallRule.source,
                    RawFirewallRule.destination,
                    RawFirewallRule.source_file,
                    RawFirewallRule.acl_name,
                    RawFirewallRule.vendor,
                    RawFirewallRule.source_port,
                    RawFirewallRule.dest_port,
                    RawFirewallRule.protocol,
                    RawFirewallRule.action,
                ]
            # Field-specific override
            mapping = {
                'source': RawFirewallRule.source,
                'destination': RawFirewallRule.destination,
                'rule_text': RawFirewallRule.rule_text,
                'raw_text': RawFirewallRule.raw_text,
                'rule_name': RawFirewallRule.rule_name,
                'action': RawFirewallRule.action,
                'protocol': RawFirewallRule.protocol,
                'acl_name': RawFirewallRule.acl_name,
                'vendor': RawFirewallRule.vendor,
                'source_port': RawFirewallRule.source_port,
                'dest_port': RawFirewallRule.dest_port,
                'source_file': RawFirewallRule.source_file,
            }
            if search_field and search_field in mapping:
                fields = [mapping[search_field]]
            from sqlalchemy import or_
            query = query.filter(or_(*[f.ilike(like) for f in fields]))

        # Sorting safety: allow only known columns
        sort_map = {
            'id': RawFirewallRule.id,
            'source_file': RawFirewallRule.source_file,
            'rule_type': RawFirewallRule.rule_type,
            'action': RawFirewallRule.action,
            'protocol': RawFirewallRule.protocol,
            'rule_name': RawFirewallRule.rule_name,
            'file_line_number': RawFirewallRule.file_line_number,
            'created_at': RawFirewallRule.created_at,
            'updated_at': RawFirewallRule.updated_at,
        }
        sort_col = sort_map.get(sort_by, RawFirewallRule.id)
        if sort_order.lower() == 'asc':
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        items = pagination.items

        return jsonify({
            'rules': [r.to_dict() for r in items],
            'pages': pagination.pages,
            'total': pagination.total,
            'current_page': page
        })
    except Exception as e:
        logger.error(f"Error getting raw rules: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/source-files', methods=['GET'])
def get_source_files():
    try:
        files = db.session.query(RawFirewallRule.source_file).distinct().all()
        source_files = [row[0] for row in files if row[0]]
        return jsonify({'source_files': source_files})
    except Exception as e:
        logger.error(f"Error getting source files: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/rules/bulk-delete', methods=['DELETE'])
def bulk_delete_raw_rules():
    try:
        data = request.get_json() or {}
        if data.get('delete_all'):
            db.session.query(RawFirewallRule).delete()
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting raw rules: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/normalized-rules', methods=['GET'])
def list_normalized_rules():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        sort_by = request.args.get('sort_by', 'id', type=str)
        sort_order = request.args.get('sort_order', 'desc', type=str)
        
        # Get all filter parameters
        source_file = request.args.get('source_file')
        search = request.args.get('search')
        search_scope = request.args.get('search_scope', 'all')
        search_fields = request.args.get('search_fields')
        action = request.args.get('action')
        protocol = request.args.get('protocol')
        compliance_status = request.args.get('compliance_status')

        query = NormalizedRule.query.filter_by(is_deleted=False)
        
        # Apply source file filter
        if source_file:
            query = query.filter_by(source_file=source_file)
        
        # Apply action filter
        if action:
            query = query.filter(NormalizedRule.action.ilike(f'%{action}%'))
        
        # Apply protocol filter
        if protocol:
            query = query.filter(NormalizedRule.protocol.ilike(f'%{protocol}%'))
        
        # Apply compliance status filter
        if compliance_status:
            query = query.filter(NormalizedRule.compliance_status.ilike(f'%{compliance_status}%'))
        
        # Apply search filter
        if search:
            search_terms = search.strip().split()
            search_conditions = []
            
            for term in search_terms:
                term_condition = []
                
                # Determine which fields to search based on search_scope
                if search_scope == 'ip':
                    # Search only IP fields
                    term_condition.extend([
                        NormalizedRule.source_ip.ilike(f'%{term}%'),
                        NormalizedRule.dest_ip.ilike(f'%{term}%'),
                        NormalizedRule.source_hostname.ilike(f'%{term}%'),
                        NormalizedRule.dest_hostname.ilike(f'%{term}%'),
                        NormalizedRule.source_subnet.ilike(f'%{term}%'),
                        NormalizedRule.dest_subnet.ilike(f'%{term}%')
                    ])
                elif search_scope == 'port':
                    # Search only port fields
                    term_condition.extend([
                        NormalizedRule.source_port.ilike(f'%{term}%'),
                        NormalizedRule.dest_port.ilike(f'%{term}%'),
                        NormalizedRule.service_port.ilike(f'%{term}%')
                    ])
                else:
                    # Search all fields (default)
                    term_condition.extend([
                        NormalizedRule.rule_name.ilike(f'%{term}%'),
                        NormalizedRule.source_ip.ilike(f'%{term}%'),
                        NormalizedRule.dest_ip.ilike(f'%{term}%'),
                        NormalizedRule.source_hostname.ilike(f'%{term}%'),
                        NormalizedRule.dest_hostname.ilike(f'%{term}%'),
                        NormalizedRule.source_owner.ilike(f'%{term}%'),
                        NormalizedRule.dest_owner.ilike(f'%{term}%'),
                        NormalizedRule.source_department.ilike(f'%{term}%'),
                        NormalizedRule.dest_department.ilike(f'%{term}%'),
                        NormalizedRule.source_environment.ilike(f'%{term}%'),
                        NormalizedRule.dest_environment.ilike(f'%{term}%'),
                        NormalizedRule.source_vlan_name.ilike(f'%{term}%'),
                        NormalizedRule.dest_vlan_name.ilike(f'%{term}%'),
                        NormalizedRule.source_subnet.ilike(f'%{term}%'),
                        NormalizedRule.dest_subnet.ilike(f'%{term}%'),
                        NormalizedRule.service_name.ilike(f'%{term}%'),
                        NormalizedRule.source_port.ilike(f'%{term}%'),
                        NormalizedRule.dest_port.ilike(f'%{term}%'),
                        NormalizedRule.service_port.ilike(f'%{term}%')
                    ])
                
                # If specific search field is specified, search only that field
                if search_fields:
                    field_mapping = {
                        'source_ip': NormalizedRule.source_ip,
                        'dest_ip': NormalizedRule.dest_ip,
                        'source_hostname': NormalizedRule.source_hostname,
                        'dest_hostname': NormalizedRule.dest_hostname,
                        'source_owner': NormalizedRule.source_owner,
                        'dest_owner': NormalizedRule.dest_owner,
                        'source_department': NormalizedRule.source_department,
                        'dest_department': NormalizedRule.dest_department,
                        'source_environment': NormalizedRule.source_environment,
                        'dest_environment': NormalizedRule.dest_environment,
                        'source_vlan_name': NormalizedRule.source_vlan_name,
                        'dest_vlan_name': NormalizedRule.dest_vlan_name,
                        'source_subnet': NormalizedRule.source_subnet,
                        'dest_subnet': NormalizedRule.dest_subnet,
                        'rule_name': NormalizedRule.rule_name,
                        'service_name': NormalizedRule.service_name,
                        'source_port': NormalizedRule.source_port,
                        'dest_port': NormalizedRule.dest_port,
                        'service_port': NormalizedRule.service_port,
                        'notes': NormalizedRule.notes
                    }
                    
                    if search_fields in field_mapping:
                        term_condition = [field_mapping[search_fields].ilike(f'%{term}%')]
                
                search_conditions.append(or_(*term_condition))
            
            if search_conditions:
                query = query.filter(and_(*search_conditions))

        sort_map = {
            'id': NormalizedRule.id,
            'source_file': NormalizedRule.source_file,
            'rule_name': NormalizedRule.rule_name,
            'action': NormalizedRule.action,
            'protocol': NormalizedRule.protocol,
            'created_at': NormalizedRule.created_at,
            'updated_at': NormalizedRule.updated_at,
            'hit_count': NormalizedRule.hit_count,
            'source_ip': NormalizedRule.source_ip,
            'dest_ip': NormalizedRule.dest_ip,
            'source_vlan_name': NormalizedRule.source_vlan_name,
            'dest_vlan_name': NormalizedRule.dest_vlan_name
        }
        col = sort_map.get(sort_by, NormalizedRule.id)
        if sort_order.lower() == 'asc':
            query = query.order_by(col.asc())
        else:
            query = query.order_by(col.desc())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        items = [r.to_summary_dict() for r in pagination.items]
        return jsonify({'normalized_rules': items, 'pages': pagination.pages, 'total': pagination.total, 'current_page': page})
    except Exception as e:
        logger.error(f"Error listing normalized rules: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/normalized-rules/<int:rule_id>/details', methods=['GET'])
def normalized_rule_details(rule_id):
    try:
        rule = NormalizedRule.query.get_or_404(rule_id)
        return jsonify(rule.to_dict())
    except Exception as e:
        logger.error(f"Error getting normalized rule details: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/object-groups', methods=['GET'])
def list_object_groups():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        status = request.args.get('status')
        group_type = request.args.get('type')
        query = ObjectGroup.query
        if status and status != 'all':
            query = query.filter(ObjectGroup.status == status)
        if group_type and group_type != 'all':
            query = query.filter(ObjectGroup.group_type == group_type)
        pagination = query.order_by(ObjectGroup.id.asc()).paginate(page=page, per_page=per_page, error_out=False)
        items = [g.to_dict() for g in pagination.items]
        return jsonify({'object_groups': items, 'total': pagination.total, 'pages': pagination.pages, 'current_page': page})
    except Exception as e:
        logger.error(f"Error listing object groups: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/service-mappings', methods=['GET'])
def list_service_mappings():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        category = request.args.get('category')
        protocol = request.args.get('protocol')
        search = request.args.get('search', '', type=str).strip()

        query = ServicePortMapping.query
        if category:
            query = query.filter(ServicePortMapping.category == category)
        if protocol:
            query = query.filter(ServicePortMapping.protocol == protocol)
        if search:
            like = f"%{search}%"
            from sqlalchemy import or_
            query = query.filter(or_(
                ServicePortMapping.service_name.ilike(like),
                ServicePortMapping.description.ilike(like)
            ))
        query = query.order_by(ServicePortMapping.id.asc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        mappings = [m.to_dict() for m in pagination.items]
        cats = [c[0] for c in db.session.query(ServicePortMapping.category).distinct().all() if c[0]]
        prots = [p[0] for p in db.session.query(ServicePortMapping.protocol).distinct().all() if p[0]]
        return jsonify({
            'mappings': mappings,
            'pagination': {'total': pagination.total, 'pages': pagination.pages, 'current_page': page},
            'filters': {'categories': cats, 'protocols': prots}
        })
    except Exception as e:
        logger.error(f"Error listing service mappings: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/service-mappings/import/iana-txt', methods=['POST'])
def import_iana_services():
    try:
        result = import_iana_service_mappings()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error importing IANA services: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/review-profiles', methods=['GET'])
def list_review_profiles():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        query = ReviewProfile.query.order_by(ReviewProfile.id.asc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        items = []
        for p in pagination.items:
            d = p.to_dict()
            try:
                # Include linked rules to support UI counters
                links = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id).all()
                d['rules'] = [
                    {
                        'id': link.id,
                        'profile_id': link.profile_id,
                        'rule_id': link.rule_id,
                        'weight': link.weight,
                        'is_mandatory': link.is_mandatory,
                        'rule_name': link.rule.rule_name if link.rule else None,
                        'rule_severity': link.rule.severity if link.rule else None,
                    }
                    for link in links
                ]
            except Exception:
                d['rules'] = []
            items.append(d)
        return jsonify({'success': True, 'data': items, 'pagination': {'total': pagination.total, 'pages': pagination.pages, 'current_page': page}})
    except Exception as e:
        logger.error(f"Error listing review profiles: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/<int:profile_id>', methods=['GET'])
def get_review_profile(profile_id):
    try:
        p = ReviewProfile.query.get_or_404(profile_id)
        d = p.to_dict()
        links = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == p.id).all()
        d['rules'] = [
            {
                'id': link.id,
                'profile_id': link.profile_id,
                'rule_id': link.rule_id,
                'weight': link.weight,
                'is_mandatory': link.is_mandatory,
                'rule_name': link.rule.rule_name if link.rule else None,
                'rule_severity': link.rule.severity if link.rule else None,
            }
            for link in links
        ]
        return jsonify(d)
    except Exception as e:
        logger.error(f"Error getting review profile {profile_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/review-profiles', methods=['POST'])
def create_review_profile():
    try:
        data = request.get_json() or {}
        p = ReviewProfile(
            profile_name=data.get('profile_name'),
            description=data.get('description'),
            compliance_framework=data.get('compliance_framework'),
            version=data.get('version'),
            is_active=bool(data.get('is_active', True)),
            created_by=data.get('created_by')
        )
        db.session.add(p)
        db.session.commit()
        return jsonify({'success': True, 'data': p.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating review profile: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/<int:profile_id>', methods=['PUT'])
def update_review_profile(profile_id):
    try:
        p = ReviewProfile.query.get_or_404(profile_id)
        data = request.get_json() or {}
        for k in ['profile_name','description','compliance_framework','version','created_by']:
            if k in data:
                setattr(p, k, data.get(k))
        if 'is_active' in data:
            p.is_active = bool(data.get('is_active'))
        db.session.commit()
        return jsonify({'success': True, 'data': p.to_dict()})
    except Exception as e:
        logger.error(f"Error updating review profile {profile_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/<int:profile_id>', methods=['DELETE'])
def delete_review_profile(profile_id):
    try:
        p = ReviewProfile.query.get_or_404(profile_id)
        db.session.delete(p)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting review profile {profile_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/<int:profile_id>/rules', methods=['POST'])
def add_rule_to_profile(profile_id):
    try:
        p = ReviewProfile.query.get_or_404(profile_id)
        data = request.get_json() or {}
        rule_id = int(data.get('rule_id'))
        weight = float(data.get('weight', 1.0))
        is_mandatory = bool(data.get('is_mandatory', True))
        link = ProfileRuleLink(profile_id=p.id, rule_id=rule_id, weight=weight, is_mandatory=is_mandatory, added_by=data.get('added_by'))
        db.session.add(link)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            # If duplicate, just return success
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error adding rule to profile {profile_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/<int:profile_id>/rules/<int:rule_id>', methods=['DELETE'])
def remove_rule_from_profile(profile_id, rule_id):
    try:
        link = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == profile_id, ProfileRuleLink.rule_id == rule_id).first()
        if not link:
            return jsonify({'success': True})
        db.session.delete(link)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error removing rule {rule_id} from profile {profile_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/review-profiles/seed-defaults', methods=['POST'])
def seed_default_profiles():
    try:
        created = []
        # Helper to get or create
        def get_or_create(name, framework, version):
            existing = ReviewProfile.query.filter(ReviewProfile.profile_name == name).first()
            if existing:
                return existing
            rp = ReviewProfile(profile_name=name, compliance_framework=framework, version=version, is_active=True, created_by='system')
            db.session.add(rp)
            db.session.commit()
            return rp
        pci = get_or_create('PCI DSS 4.0.1 Template', 'PCI-DSS', '4.0.1')
        iso = get_or_create('ISO 27001 Baseline', 'ISO27001', '2013')
        created.extend([pci.to_dict(), iso.to_dict()])
        # Link some existing rules if present
        sample_rules = ComplianceRule.query.limit(10).all()
        for r in sample_rules:
            for prof in [pci, iso]:
                exists = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == prof.id, ProfileRuleLink.rule_id == r.id).first()
                if not exists:
                    db.session.add(ProfileRuleLink(profile_id=prof.id, rule_id=r.id, weight=1.0, is_mandatory=True, added_by='system'))
        db.session.commit()
        return jsonify({'success': True, 'profiles': created})
    except Exception as e:
        logger.error(f"Error seeding default profiles: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
@app.route('/api/cmdb', methods=['GET'])
def list_cmdb_assets():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        search = request.args.get('search', '', type=str).strip()

        query = CMDBAsset.query
        if search:
            like = f"%{search}%"
            from sqlalchemy import or_
            query = query.filter(or_(
                CMDBAsset.hostname.ilike(like),
                CMDBAsset.ip_address.ilike(like),
                CMDBAsset.owner.ilike(like),
                CMDBAsset.department.ilike(like),
                CMDBAsset.asset_type.ilike(like),
                CMDBAsset.operating_system.ilike(like),
                CMDBAsset.location.ilike(like),
                CMDBAsset.additional_data.ilike(like)
            ))
        query = query.order_by(CMDBAsset.id.asc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        items = [a.to_dict() for a in pagination.items]
        return jsonify({'assets': items, 'total': pagination.total, 'pages': pagination.pages, 'current_page': page})
    except Exception as e:
        logger.error(f"Error listing CMDB assets: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cmdb/available-fields', methods=['GET'])
def cmdb_available_fields():
    try:
        source_file = request.args.get('source_file')
        q = CMDBAsset.query
        if source_file:
            q = q.filter(CMDBAsset.source_file == source_file)
        assets = q.limit(200).all()
        fields = set([
            'hostname','ip_address','owner','department','asset_type','operating_system','location','status',
            'environment','manufacturer','model','os_version','mac_address','serial_number','asset_tag','business_unit',
            'cost_center','application_name','description','pcidss_asset_category'
        ])
        import json as _json
        for a in assets:
            try:
                add = _json.loads(a.additional_data) if a.additional_data else {}
                for k in (add or {}).keys():
                    fields.add(str(k))
            except Exception:
                continue
        return jsonify({'fields': sorted(list(fields))})
    except Exception as e:
        logger.error(f"Error getting CMDB available fields: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cmdb', methods=['POST'])
def create_cmdb_asset():
    try:
        data = request.get_json() or {}
        asset = CMDBAsset(
            source_file=data.get('source_file') or 'manual',
            hostname=data.get('hostname'),
            ip_address=data.get('ip_address'),
            owner=data.get('owner'),
            department=data.get('department'),
            asset_type=data.get('asset_type'),
            operating_system=data.get('operating_system'),
            location=data.get('location'),
            status=data.get('status') or 'active',
            os_version=data.get('os_version'),
            mac_address=data.get('mac_address'),
            serial_number=data.get('serial_number'),
            asset_tag=data.get('asset_tag'),
            business_unit=data.get('business_unit'),
            cost_center=data.get('cost_center'),
            environment=data.get('environment'),
            manufacturer=data.get('manufacturer'),
            model=data.get('model'),
            additional_data=(data.get('additional_data') and (lambda x: __import__('json').dumps(x))(data.get('additional_data'))) or None,
        )
        db.session.add(asset)
        db.session.commit()
        return jsonify({'asset': asset.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating CMDB asset: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cmdb/<int:asset_id>', methods=['PUT'])
def update_cmdb_asset(asset_id):
    try:
        asset = CMDBAsset.query.get_or_404(asset_id)
        data = request.get_json() or {}
        for field in ['hostname','ip_address','owner','department','asset_type','operating_system','location','status',
                      'os_version','mac_address','serial_number','asset_tag','business_unit','cost_center','environment',
                      'manufacturer','model']:
            if field in data:
                setattr(asset, field, data.get(field))
        if 'additional_data' in data:
            import json as _json
            asset.additional_data = _json.dumps(data.get('additional_data') or {})
        db.session.commit()
        return jsonify({'asset': asset.to_dict()})
    except Exception as e:
        logger.error(f"Error updating CMDB asset {asset_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cmdb/<int:asset_id>', methods=['DELETE'])
def delete_cmdb_asset(asset_id):
    try:
        asset = CMDBAsset.query.get_or_404(asset_id)
        db.session.delete(asset)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting CMDB asset {asset_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/reviews/results', methods=['GET'])
def list_review_results():
    try:
        from review_engine import get_review_results
        session_id = request.args.get('session_id')
        status = request.args.get('status')
        rule_name = request.args.get('rule_name')
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        res = get_review_results(review_session_id=session_id, limit=limit, offset=offset, rule_name=rule_name, status=status)
        if res.get('success'):
            return jsonify({'success': True, 'data': res.get('results', []), 'total_count': res.get('total_count', 0), 'returned_count': res.get('returned_count', 0)})
        else:
            return jsonify({'success': False, 'error': res.get('error', 'Internal error'), 'data': [], 'total_count': 0}), 500
    except Exception as e:
        logger.error(f"Error listing review results: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/reviews/results/bulk-delete', methods=['DELETE'])
def bulk_delete_review_results():
    try:
        data = request.get_json() or {}
        if data.get('delete_all'):
            db.session.query(ReviewResult).delete()
            db.session.commit()
            return jsonify({'success': True})
        session_id = data.get('session_id')
        if session_id:
            db.session.query(ReviewResult).filter(ReviewResult.review_session_id == session_id).delete()
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    except Exception as e:
        logger.error(f"Error bulk deleting review results: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/compliance/metrics', methods=['GET'])
def compliance_metrics():
    try:
        total_rules = db.session.query(ComplianceRule).count()
        total_profiles = db.session.query(ReviewProfile).count()
        total_normalized = db.session.query(NormalizedRule).count()
        compliant = db.session.query(ReviewResult).filter(ReviewResult.status == 'compliant').count()
        non_compliant = db.session.query(ReviewResult).filter(ReviewResult.status == 'non_compliant').count()
        overall = round((compliant / (compliant + non_compliant)) * 100, 2) if (compliant + non_compliant) else 0
        return jsonify({
            'overallScore': overall,
            'totalRules': total_rules,
            'compliantRules': compliant,
            'warningRules': 0,
            'violationRules': non_compliant,
        })
    except Exception as e:
        logger.error(f"Error getting compliance metrics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance/dashboard/profile/<int:profile_id>', methods=['GET'])
def compliance_dashboard_profile(profile_id):
    try:
        range_param = (request.args.get('range') or '30').lower()
        bucket = (request.args.get('bucket') or 'day').lower()
        profile_id_b = request.args.get('profile_id_b', type=int)

        def build_dashboard_for_profile(pid: int):
            base_query = ReviewResult.query.filter(ReviewResult.profile_id == pid)

            if range_param in ('7', '30', '90'):
                days = int(range_param)
                cutoff = datetime.utcnow() - timedelta(days=days)
                base_query = base_query.filter(ReviewResult.checked_at >= cutoff)

            results = base_query.all()

            if not results:
                return {
                    'summary': {
                        'total_rules': 0,
                        'compliant_rules': 0,
                        'non_compliant_rules': 0,
                        'compliance_percentage': 0.0,
                    },
                    'violations_by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                    'top_violations': [],
                    'compliance_trends': [],
                    'metric_trends': [],
                    'severity_over_time': [],
                    'sessions': [],
                    'rule_summary': [],
                }

            latest_by_nr = {}
            for r in results:
                key = (r.normalized_rule_id, r.compliance_rule_id)
                prev = latest_by_nr.get(key)
                if not prev or (r.checked_at and r.checked_at > prev.checked_at):
                    latest_by_nr[key] = r

            compliant_rules = 0
            non_compliant_rules = 0
            seen_nr = set()
            for (nr_id, _), r in latest_by_nr.items():
                if nr_id in seen_nr:
                    continue
                seen_nr.add(nr_id)
                if r.status == 'compliant':
                    compliant_rules += 1
                elif r.status == 'non_compliant':
                    non_compliant_rules += 1

            total_rules = compliant_rules + non_compliant_rules
            compliance_percentage = round(
                (compliant_rules / total_rules) * 100, 2
            ) if total_rules else 0.0

            sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for r in results:
                if r.status == 'non_compliant' and r.severity in sev_counts:
                    sev_counts[r.severity] += 1

            top_map = {}
            for r in results:
                if r.status != 'non_compliant':
                    continue
                cr = r.compliance_rule
                rule_id = cr.id if cr else r.compliance_rule_id
                rule_name = cr.rule_name if cr and cr.rule_name else 'Unknown'
                severity = cr.severity if cr and cr.severity else (r.severity or 'Medium')
                key = rule_id
                if key not in top_map:
                    top_map[key] = {
                        'rule_id': rule_id,
                        'rule_name': rule_name,
                        'violation_count': 0,
                        'severity': severity,
                    }
                top_map[key]['violation_count'] += 1
            top_violations = sorted(
                top_map.values(),
                key=lambda x: x['violation_count'],
                reverse=True
            )

            def bucket_key(dt):
                if not dt:
                    return None
                if bucket == 'month':
                    return dt.strftime('%Y-%m')
                if bucket == 'week':
                    year, week, _ = dt.isocalendar()
                    return f'{year}-W{week:02d}'
                return dt.date().isoformat()

            trend_map = {}
            severity_time = {}
            for r in results:
                k = bucket_key(r.checked_at)
                if not k:
                    continue
                if k not in trend_map:
                    trend_map[k] = {'total': 0, 'compliant': 0, 'non_compliant': 0}
                trend_map[k]['total'] += 1
                if r.status == 'compliant':
                    trend_map[k]['compliant'] += 1
                elif r.status == 'non_compliant':
                    trend_map[k]['non_compliant'] += 1

                if r.status == 'non_compliant':
                    if k not in severity_time:
                        severity_time[k] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                    sev = r.severity or 'Medium'
                    if sev not in severity_time[k]:
                        severity_time[k][sev] = 0
                    severity_time[k][sev] += 1

            metric_trends = []
            for d in sorted(trend_map.keys()):
                t = trend_map[d]
                tot = t['total']
                cp = round((t['compliant'] / tot) * 100, 2) if tot else 0.0
                metric_trends.append({
                    'date': d,
                    'total_rules': tot,
                    'compliant_rules': t['compliant'],
                    'non_compliant_rules': t['non_compliant'],
                    'compliance_percentage': cp,
                })

            severity_over_time = []
            for d in sorted(severity_time.keys()):
                row = {'date': d}
                row.update(severity_time[d])
                severity_over_time.append(row)

            sessions_q = (
                db.session.query(
                    ReviewResult.review_session_id,
                    db.func.max(ReviewResult.checked_at).label('checked_at'),
                )
                .filter(ReviewResult.profile_id == pid)
            )
            if range_param in ('7', '30', '90'):
                days = int(range_param)
                cutoff = datetime.utcnow() - timedelta(days=days)
                sessions_q = sessions_q.filter(ReviewResult.checked_at >= cutoff)
            sessions_q = sessions_q.group_by(ReviewResult.review_session_id).order_by(
                db.func.max(ReviewResult.checked_at).desc()
            )
            sessions_rows = sessions_q.all()
            sessions = [
                {
                    'review_session_id': row.review_session_id,
                    'checked_at': row.checked_at.isoformat() if hasattr(row.checked_at, 'isoformat') else None,
                }
                for row in sessions_rows
            ]

            rule_summary_map = {}
            for r in results:
                cr = r.compliance_rule
                rid = cr.id if cr else r.compliance_rule_id
                key = rid
                if key not in rule_summary_map:
                    rule_summary_map[key] = {
                        'rule_id': rid,
                        'rule_name': cr.rule_name if cr and cr.rule_name else None,
                        'severity': cr.severity if cr and cr.severity else (r.severity or None),
                        'compliant_count': 0,
                        'non_compliant_count': 0,
                    }
                if r.status == 'compliant':
                    rule_summary_map[key]['compliant_count'] += 1
                elif r.status == 'non_compliant':
                    rule_summary_map[key]['non_compliant_count'] += 1

            rule_summary = sorted(
                rule_summary_map.values(),
                key=lambda x: x['non_compliant_count'],
                reverse=True,
            )

            return {
                'summary': {
                    'total_rules': total_rules,
                    'compliant_rules': compliant_rules,
                    'non_compliant_rules': non_compliant_rules,
                    'compliance_percentage': compliance_percentage,
                },
                'violations_by_severity': sev_counts,
                'top_violations': top_violations,
                'compliance_trends': metric_trends,
                'metric_trends': metric_trends,
                'severity_over_time': severity_over_time,
                'sessions': sessions,
                'rule_summary': rule_summary,
            }

        data_a = build_dashboard_for_profile(profile_id)
        response = dict(data_a)

        if profile_id_b:
            data_b = build_dashboard_for_profile(profile_id_b)
            response['metric_trends_b'] = data_b.get('metric_trends', [])
            response['severity_over_time_b'] = data_b.get('severity_over_time', [])
            response['sessions_b'] = data_b.get('sessions', [])

        return jsonify(response)
        from sqlalchemy import text
        q = text("SELECT status, severity, compliance_rule_id FROM review_results WHERE profile_id = :pid")
        rows = db.session.execute(q, {'pid': profile_id}).fetchall()
        sev = {'Critical':0,'High':0,'Medium':0,'Low':0}
        for r in rows:
            if r.status == 'non_compliant' and r.severity in sev:
                sev[r.severity] += 1
        top = []
        if rows:
            q2 = text("SELECT cr.rule_name, COUNT(*) AS c FROM review_results rr LEFT JOIN compliance_rules cr ON rr.compliance_rule_id = cr.id WHERE rr.profile_id = :pid AND rr.status = 'non_compliant' GROUP BY rr.compliance_rule_id ORDER BY c DESC LIMIT 10")
            top = [{'rule_name': t.rule_name or 'Unknown', 'count': t.c} for t in db.session.execute(q2, {'pid': profile_id}).fetchall()]
        return jsonify({
            'summary': {'profile_id': profile_id},
            'violations_by_severity': sev,
            'top_violations': top,
            'compliance_trends': [],
            'severity_over_time': [],
            'sessions': []
        })
    except Exception as e:
        logger.error(f"Error getting dashboard profile {profile_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance/violations/examples', methods=['GET'])
def compliance_violation_examples():
    try:
        profile_id = request.args.get('profile_id', type=int)
        rule_id = request.args.get('rule_id', type=int)
        session_id = request.args.get('session_id', type=str)
        limit = request.args.get('limit', type=int) or 10

        if not profile_id or not rule_id:
            return jsonify({'examples': []})

        query = ReviewResult.query.filter(
            ReviewResult.profile_id == profile_id,
            ReviewResult.compliance_rule_id == rule_id,
            ReviewResult.status == 'non_compliant',
        )
        if session_id:
            query = query.filter(ReviewResult.review_session_id == session_id)

        query = query.order_by(ReviewResult.checked_at.desc()).limit(limit)
        rows = query.all()

        examples = []
        for r in rows:
            nr = r.normalized_rule
            failed_checks = r.failed_checks or []
            try:
                if isinstance(failed_checks, str):
                    failed_checks = json.loads(failed_checks)
            except Exception:
                failed_checks = []

            examples.append(
                {
                    'review_result_id': r.id,
                    'review_session_id': r.review_session_id,
                    'checked_at': r.checked_at.isoformat() if r.checked_at else None,
                    'source_file': getattr(nr, 'source_file', None),
                    'action': getattr(nr, 'action', None),
                    'protocol': getattr(nr, 'protocol', None),
                    'source_ip': getattr(nr, 'source_ip', None),
                    'dest_ip': getattr(nr, 'dest_ip', None),
                    'service_port': getattr(nr, 'dest_port', None),
                    'failed_checks': failed_checks,
                }
            )

        return jsonify({'examples': examples})
    except Exception as e:
        logger.error(f"Error getting violation examples: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/compliance/evaluate/profile/<int:profile_id>', methods=['GET'])
def evaluate_profile(profile_id):
    try:
        engine = ComplianceEngine()
        result = engine.evaluate_all_rules_against_profile(profile_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error evaluating profile {profile_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reviews/run/<int:profile_id>', methods=['POST'])
def run_review(profile_id):
    try:
        result = run_review_process(profile_id)
        status_code = 200 if result.get('success') else 400
        if result.get('success'):
            wrapped = {
                'success': True,
                'data': {
                    'review_session_id': result.get('review_session_id'),
                    'profile_name': result.get('profile_name'),
                    'execution_time': result.get('execution_time'),
                },
                'statistics': result.get('statistics')
            }
            return jsonify(wrapped), status_code
        else:
            return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error running review for profile {profile_id}: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/reviews/run-one/<int:profile_id>/<int:nr_id>', methods=['POST'])
def run_review_one(profile_id: int, nr_id: int):
    try:
        # Minimal single-rule runner that persists a ReviewResult for the given profile and normalized rule
        profile = ReviewProfile.query.get_or_404(profile_id)
        nr = NormalizedRule.query.get_or_404(nr_id)
        # Collect active rules linked to profile
        links = ProfileRuleLink.query.filter(ProfileRuleLink.profile_id == profile_id).all()
        rules = [l.rule for l in links if l.rule and l.rule.is_active]
        review_session_id = str(uuid.uuid4())
        engine = ComplianceEngine()
        results = []
        for rule in rules:
            # Early compliant for deny/block/drop
            action_raw = str(getattr(nr, 'action', '') or '').strip().lower()
            action_tokens = [t.strip() for t in re.split(r"[;\,\|\s]+", action_raw) if t.strip()]
            if any(t in ('deny','block','drop') for t in action_tokens):
                status = 'compliant'
                failed_checks = []
            else:
                eval_res = engine.evaluate_rule_against_compliance(nr, rule)
                status = 'non_compliant' if not eval_res.get('compliant', True) else 'compliant'
                failed_checks = []
                if status == 'non_compliant':
                    failed_checks.append({
                        'rule_name': rule.rule_name,
                        'field_checked': rule.field_to_check,
                        'operator': rule.operator,
                        'expected_value': rule.value,
                        'actual_value': eval_res.get('field_value', ''),
                        'description': rule.description
                    })
            rr = ReviewResult(
                normalized_rule_id=nr.id,
                compliance_rule_id=rule.id,
                profile_id=profile_id,
                review_session_id=review_session_id,
                status=status,
                failed_checks=json.dumps(failed_checks) if failed_checks else None,
                severity=rule.severity if status == 'non_compliant' else None,
                notes=f"Single-run check on {datetime.utcnow().isoformat()}"
            )
            db.session.add(rr)
            results.append({'rule_id': rule.id, 'rule_name': rule.rule_name, 'status': status})
        db.session.commit()
        return jsonify({'success': True, 'review_session_id': review_session_id, 'results': results})
    except Exception as e:
        logger.error(f"Error running single review for profile {profile_id}, NR {nr_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-fields', methods=['GET'])
def list_custom_fields():
    try:
        fields_raw = CustomFieldModel.query.order_by(CustomFieldModel.id.asc()).all()
        fields = []
        for f in fields_raw:
            d = f.to_dict()
            d['is_mandatory'] = 1 if bool(d.get('is_mandatory')) else 0
            d['is_important'] = 1 if bool(d.get('is_important')) else 0
            if bool(d.get('is_active', True)):
                fields.append(d)
        return jsonify({'success': True, 'data': fields})
    except Exception as e:
        logger.error(f"Error listing custom fields: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-fields', methods=['POST'])
def create_custom_field():
    try:
        data = request.get_json() or {}
        field = CustomFieldModel(
            field_name=data.get('field_name'),
            display_name=data.get('display_name'),
            description=data.get('description'),
            field_type=data.get('field_type') or 'text',
            file_type=data.get('file_type') or 'firewall',
            is_mandatory=bool(data.get('is_mandatory')),
            is_important=bool(data.get('is_important')),
            default_value=data.get('default_value'),
            validation_rules=data.get('validation_rules'),
            is_active=bool(data.get('is_active', True)),
            created_by=data.get('created_by'),
        )
        db.session.add(field)
        db.session.commit()
        return jsonify({'success': True, 'data': field.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating custom field: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-fields/<int:field_id>', methods=['PUT'])
def update_custom_field(field_id):
    try:
        field = CustomFieldModel.query.get_or_404(field_id)
        data = request.get_json() or {}
        for k in ['field_name','display_name','description','field_type','file_type','default_value','validation_rules','created_by']:
            if k in data:
                setattr(field, k, data.get(k))
        for k in ['is_mandatory','is_important','is_active']:
            if k in data:
                setattr(field, k, bool(data.get(k)))
        db.session.commit()
        return jsonify({'success': True, 'data': field.to_dict()})
    except Exception as e:
        logger.error(f"Error updating custom field {field_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-fields/<int:field_id>', methods=['DELETE'])
def delete_custom_field(field_id):
    try:
        field = CustomFieldModel.query.get_or_404(field_id)
        db.session.delete(field)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting custom field {field_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-fields/file-type/<string:file_type>', methods=['GET'])
def list_custom_fields_by_type(file_type):
    try:
        fields_raw = CustomFieldModel.query.filter(CustomFieldModel.file_type == file_type).order_by(CustomFieldModel.id.asc()).all()
        fields = []
        for f in fields_raw:
            d = f.to_dict()
            d['is_mandatory'] = 1 if bool(d.get('is_mandatory')) else 0
            d['is_important'] = 1 if bool(d.get('is_important')) else 0
            if bool(d.get('is_active', True)):
                fields.append(d)
        return jsonify({'success': True, 'data': fields})
    except Exception as e:
        logger.error(f"Error listing custom fields by type {file_type}: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-rules', methods=['GET'])
def list_custom_rules():
    try:
        rules = [r.to_dict() for r in CustomRuleModel.query.order_by(CustomRuleModel.id.asc()).all()]
        return jsonify({'success': True, 'data': rules})
    except Exception as e:
        logger.error(f"Error listing custom rules: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-rules', methods=['POST'])
def create_custom_rule():
    try:
        data = request.get_json() or {}
        rule = CustomRuleModel(
            field_id=data.get('field_id'),
            rule_name=data.get('rule_name'),
            description=data.get('description'),
            condition_type=data.get('condition_type') or 'threshold',
            condition_value=data.get('condition_value') or '',
            action=data.get('action') or 'alert',
            severity=data.get('severity') or 'medium',
            is_active=bool(data.get('is_active', True)),
            created_by=data.get('created_by'),
        )
        db.session.add(rule)
        db.session.commit()
        return jsonify({'success': True, 'data': rule.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating custom rule: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-rules/<int:rule_id>', methods=['PUT'])
def update_custom_rule(rule_id):
    try:
        rule = CustomRuleModel.query.get_or_404(rule_id)
        data = request.get_json() or {}
        for k in ['field_id','rule_name','description','condition_type','condition_value','action','severity','created_by']:
            if k in data:
                setattr(rule, k, data.get(k))
        if 'is_active' in data:
            rule.is_active = bool(data.get('is_active'))
        db.session.commit()
        return jsonify({'success': True, 'data': rule.to_dict()})
    except Exception as e:
        logger.error(f"Error updating custom rule {rule_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-rules/<int:rule_id>', methods=['DELETE'])
def delete_custom_rule(rule_id):
    try:
        rule = CustomRuleModel.query.get_or_404(rule_id)
        db.session.delete(rule)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting custom rule {rule_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/custom-rules/evaluate', methods=['POST'])
def evaluate_custom_rules():
    try:
        return jsonify({'success': True, 'data': []})
    except Exception as e:
        logger.error(f"Error evaluating custom rules: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/available-fields/<string:file_type>', methods=['GET'])
def available_fields(file_type):
    try:
        base_fields = []
        if file_type == 'firewall':
            base_fields = [
                {'value': 'rule_name', 'label': 'Rule Name', 'description': 'Rule name', 'mandatory': False, 'important': True},
                {'value': 'rule_type', 'label': 'Rule Type', 'description': 'Rule type/classification', 'mandatory': False, 'important': False},
                {'value': 'source', 'label': 'Source', 'description': 'Source object/group', 'mandatory': False, 'important': True},
                {'value': 'destination', 'label': 'Destination', 'description': 'Destination object/group', 'mandatory': False, 'important': True},
                {'value': 'source_ip', 'label': 'Source IP', 'description': 'Source IP address', 'mandatory': False, 'important': True},
                {'value': 'dest_ip', 'label': 'Destination IP', 'description': 'Destination IP address', 'mandatory': False, 'important': True},
                {'value': 'source_port', 'label': 'Source Port', 'description': 'Source port number/name', 'mandatory': False, 'important': False},
                {'value': 'service', 'label': 'Service (Name/Port)', 'description': 'Unified service field (name or port or proto/port)', 'mandatory': False, 'important': True},
                {'value': 'dest_port', 'label': 'Destination Port', 'description': 'Destination port number/name', 'mandatory': False, 'important': True},
                {'value': 'service_port', 'label': 'Service Port', 'description': 'Service port (destination)', 'mandatory': False, 'important': True},
                {'value': 'service_name', 'label': 'Service Name', 'description': 'Service name', 'mandatory': False, 'important': False},
                {'value': 'action', 'label': 'Action', 'description': 'permit/deny', 'mandatory': True, 'important': True},
                {'value': 'protocol', 'label': 'Protocol', 'description': 'tcp/udp/icmp/ip (auto-detected if omitted)', 'mandatory': False, 'important': False},
                {'value': 'source_zone', 'label': 'Source Zone', 'description': 'Source security zone', 'mandatory': False, 'important': False},
                {'value': 'dest_zone', 'label': 'Destination Zone', 'description': 'Destination security zone', 'mandatory': False, 'important': False},
                {'value': 'application', 'label': 'Application', 'description': 'Application name/tag', 'mandatory': False, 'important': False},
                {'value': 'hit_count', 'label': 'Hit Count', 'description': 'Total hits', 'mandatory': False, 'important': False},
            ]
        elif file_type == 'cmdb':
            base_fields = [
                {'value': 'hostname', 'label': 'Hostname', 'description': 'Asset hostname', 'mandatory': False, 'important': True},
                {'value': 'ip_address', 'label': 'IP Address', 'description': 'Asset IP address', 'mandatory': False, 'important': True},
                {'value': 'owner', 'label': 'Owner', 'description': 'Asset owner', 'mandatory': False, 'important': False},
                {'value': 'department', 'label': 'Department', 'description': 'Owning department', 'mandatory': False, 'important': False},
                {'value': 'environment', 'label': 'Environment', 'description': 'Prod/Dev/UAT/etc', 'mandatory': False, 'important': False},
                {'value': 'business_unit', 'label': 'Business Unit', 'description': 'Business unit/cost center', 'mandatory': False, 'important': False},
                {'value': 'location', 'label': 'Location', 'description': 'Physical/logical location', 'mandatory': False, 'important': False},
                {'value': 'asset_type', 'label': 'Asset Type', 'description': 'Server/DB/Network/etc', 'mandatory': False, 'important': False},
                {'value': 'operating_system', 'label': 'Operating System', 'description': 'OS name', 'mandatory': False, 'important': False},
                {'value': 'os_version', 'label': 'OS Version', 'description': 'OS version', 'mandatory': False, 'important': False},
                {'value': 'manufacturer', 'label': 'Manufacturer', 'description': 'Vendor', 'mandatory': False, 'important': False},
                {'value': 'model', 'label': 'Model', 'description': 'Hardware model', 'mandatory': False, 'important': False},
                {'value': 'mac_address', 'label': 'MAC Address', 'description': 'MAC address', 'mandatory': False, 'important': False},
                {'value': 'serial_number', 'label': 'Serial Number', 'description': 'Serial', 'mandatory': False, 'important': False},
                {'value': 'asset_tag', 'label': 'Asset Tag', 'description': 'Asset tag/id', 'mandatory': False, 'important': False},
                {'value': 'application_name', 'label': 'Application Name', 'description': 'Application name', 'mandatory': False, 'important': True},
                {'value': 'pcidss_asset_category', 'label': 'PCI DSS Category', 'description': 'PCI DSS asset category', 'mandatory': False, 'important': True},
                {'value': 'cost_center', 'label': 'Cost Center', 'description': 'Cost center code', 'mandatory': False, 'important': False},
                {'value': 'status', 'label': 'Status', 'description': 'Active/Retired/etc', 'mandatory': False, 'important': False},
            ]
        elif file_type == 'vlan':
            base_fields = [
                {'value': 'vlan_id', 'label': 'VLAN ID', 'description': 'VLAN identifier', 'mandatory': True, 'important': True},
                {'value': 'name', 'label': 'Name', 'description': 'VLAN name', 'mandatory': False, 'important': False},
                {'value': 'subnet', 'label': 'Subnet', 'description': 'CIDR subnet', 'mandatory': False, 'important': True},
                {'value': 'gateway', 'label': 'Gateway', 'description': 'Default gateway', 'mandatory': False, 'important': False},
                {'value': 'location', 'label': 'Location', 'description': 'Site/location', 'mandatory': False, 'important': False},
                {'value': 'vlan_type', 'label': 'VLAN Type', 'description': 'Access/Trunk/etc', 'mandatory': False, 'important': False},
                {'value': 'status', 'label': 'Status', 'description': 'Active/Retired/etc', 'mandatory': False, 'important': False},
            ]
        elif file_type == 'objects':
            base_fields = [
                {'value': 'name', 'label': 'Object Name', 'description': 'Name of the object group', 'mandatory': True, 'important': True},
                {'value': 'members', 'label': 'Object Items', 'description': 'IP, hostname, Range, etc.', 'mandatory': True, 'important': True},
                {'value': 'description', 'label': 'Description', 'description': 'Description', 'mandatory': False, 'important': False},
                {'value': 'group_type', 'label': 'Group Type', 'description': 'network/service', 'mandatory': False, 'important': False},
            ]
        return jsonify({'fields': base_fields})
    except Exception as e:
        logger.error(f"Error getting available fields for {file_type}: {e}")
        return jsonify({'error': 'Internal server error'}), 500
@app.route('/api/vlans', methods=['GET'])
def list_vlans():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        search = request.args.get('search', '', type=str).strip()
        query = VLANNetwork.query
        if search:
            like = f"%{search}%"
            from sqlalchemy import or_
            query = query.filter(or_(
                VLANNetwork.name.ilike(like),
                VLANNetwork.subnet.ilike(like),
                VLANNetwork.description.ilike(like),
                VLANNetwork.location.ilike(like)
            ))
        pagination = query.order_by(VLANNetwork.id.asc()).paginate(page=page, per_page=per_page, error_out=False)
        items = [v.to_dict() for v in pagination.items]
        return jsonify({'vlans': items, 'total': pagination.total, 'pages': pagination.pages, 'current_page': page})
    except Exception as e:
        logger.error(f"Error listing VLANs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vlans', methods=['POST'])
def create_vlan():
    try:
        data = request.get_json() or {}
        vlan = VLANNetwork(
            source_file=data.get('source_file') or 'manual',
            vlan_id=data.get('vlan_id'),
            name=data.get('name'),
            subnet=data.get('subnet'),
            gateway=data.get('gateway'),
            description=data.get('description'),
            location=data.get('location'),
            status=data.get('status') or 'active',
            vlan_type=data.get('vlan_type') or 'access'
        )
        db.session.add(vlan)
        db.session.commit()
        return jsonify({'vlan': vlan.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating VLAN: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vlans/<int:vlan_id>', methods=['PUT'])
def update_vlan(vlan_id):
    try:
        vlan = VLANNetwork.query.get_or_404(vlan_id)
        data = request.get_json() or {}
        for field in ['vlan_id','name','subnet','gateway','description','location','status','vlan_type']:
            if field in data:
                setattr(vlan, field, data.get(field))
        db.session.commit()
        return jsonify({'vlan': vlan.to_dict()})
    except Exception as e:
        logger.error(f"Error updating VLAN {vlan_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vlans/<int:vlan_id>', methods=['DELETE'])
def delete_vlan(vlan_id):
    try:
        vlan = VLANNetwork.query.get_or_404(vlan_id)
        db.session.delete(vlan)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting VLAN {vlan_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/vlans/bulk-delete', methods=['DELETE'])
def bulk_delete_vlans():
    try:
        data = request.get_json() or {}
        if data.get('delete_all'):
            db.session.query(VLANNetwork).delete()
            db.session.commit()
            return jsonify({'success': True})
        
        vlan_ids = data.get('vlan_ids')
        if vlan_ids and isinstance(vlan_ids, list):
            db.session.query(VLANNetwork).filter(VLANNetwork.id.in_(vlan_ids)).delete(synchronize_session=False)
            db.session.commit()
            return jsonify({'success': True})
            
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    except Exception as e:
        logger.error(f"Error bulk deleting VLANs: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    try:
        upload = request.files.get('file')
        file_type = request.form.get('file_type') or 'firewall'
        if not upload:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400

        filename = upload.filename or ''
        name_lower = filename.lower()
        preview_data = []
        columns = []
        total_rows = 0

        # Read small buffer and try CSV parsing
        try:
            content = upload.stream.read()
        except Exception:
            content = upload.read()
        if isinstance(content, bytes):
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except Exception:
                text_content = content.decode('latin-1', errors='ignore')
        else:
            text_content = str(content)

        # Detect text firewall configs and parse with FirewallParser
        is_text_cfg = False
        if (file_type or '').lower() == 'firewall':
            if name_lower.endswith('.txt') or name_lower.endswith('.conf') or ('access-list' in (text_content.lower() if text_content else '')):
                is_text_cfg = True
        if is_text_cfg:
            try:
                temp_fp = os.path.join(_get_uploads_dir(), f"_analyze_{uuid.uuid4().hex}.txt")
                with open(temp_fp, 'w', encoding='utf-8') as fh:
                    fh.write(text_content or '')
                parsed = parser_factory.parse_file(temp_fp, 'firewall', vendor='auto')
                try:
                    os.remove(temp_fp)
                except Exception:
                    pass
                total_rows = len(parsed)
                for rec in parsed[:10]:
                    preview_data.append({
                        'acl_name': rec.get('acl_name'),
                        'line_number_in_acl': rec.get('line_number_in_acl'),
                        'action': rec.get('action'),
                        'protocol': rec.get('protocol'),
                        'source': rec.get('source'),
                        'destination': rec.get('destination'),
                        'dest_port': rec.get('dest_port'),
                    })
                return jsonify({
                    'success': True,
                    'detected_fields': {},
                    'suggestions': {},
                    'preview_data': preview_data,
                    'confidence_scores': {},
                    'field_priorities': {},
                    'mandatory_missing': [],
                    'important_missing': [],
                    'columns': [],
                    'total_rows': total_rows,
                    'file_type': file_type,
                    'is_text_config': True,
                    'format_info': {'filename': filename}
                })
            except Exception as e:
                logger.error(f"Error parsing text firewall config: {e}")
                # fall through to CSV heuristics

        # Basic CSV detection: robust parsing
        try:
            # Handle BOM if present
            if text_content.startswith('\ufeff'):
                text_content = text_content[1:]
            
            # Use StringIO for proper CSV handling (quotes, newlines)
            f = io.StringIO(text_content)
            # Read first few lines for preview
            sample_lines = []
            for _ in range(200):
                line = f.readline()
                if not line: break
                sample_lines.append(line)
            
            f_sample = io.StringIO(''.join(sample_lines))
            reader = csv.reader(f_sample)
            rows = list(reader)
            if rows:
                columns = [c.strip() for c in rows[0]]
                for r in rows[1:6]:
                    row_dict = {}
                    for i, col in enumerate(columns):
                        row_dict[col] = r[i] if i < len(r) else ''
                    preview_data.append(row_dict)
                total_rows = max(0, len(rows) - 1)
        except Exception:
            columns = []
            preview_data = []
            total_rows = 0

        # Heuristics for detected fields and suggestions
        def norm(s):
            return (s or '').strip().lower().replace('-', '_').replace(' ', '_')

        available = []
        try:
            # Reuse available fields endpoint logic
            fields = [
                {'value': 'source_ip', 'label': 'Source IP', 'description': 'Source IP address', 'mandatory': False, 'important': True},
                {'value': 'dest_ip', 'label': 'Destination IP', 'description': 'Destination IP address', 'mandatory': False, 'important': True},
                {'value': 'service_port', 'label': 'Service Port', 'description': 'Destination service port', 'mandatory': False, 'important': True},
                {'value': 'action', 'label': 'Action', 'description': 'permit/deny', 'mandatory': False, 'important': True},
                {'value': 'protocol', 'label': 'Protocol', 'description': 'tcp/udp/icmp/ip', 'mandatory': False, 'important': False},
                {'value': 'source_zone', 'label': 'Source Zone', 'description': 'Source zone', 'mandatory': False, 'important': False},
                {'value': 'dest_zone', 'label': 'Destination Zone', 'description': 'Destination zone', 'mandatory': False, 'important': False},
                {'value': 'rule_name', 'label': 'Rule Name', 'description': 'Rule name', 'mandatory': False, 'important': True},
                {'value': 'hit_count', 'label': 'Hit Count', 'description': 'Total hits', 'mandatory': False, 'important': False},
                {'value': 'destination', 'label': 'Destination', 'description': 'Destination object/group', 'mandatory': False, 'important': False},
                {'value': 'source', 'label': 'Source', 'description': 'Source object/group', 'mandatory': False, 'important': False},
                {'value': 'dest_port', 'label': 'Destination Port', 'description': 'Destination port name', 'mandatory': False, 'important': False},
                {'value': 'source_vlan_id', 'label': 'Source VLAN ID', 'description': 'Source VLAN ID', 'mandatory': False, 'important': False},
                {'value': 'source_vlan_name', 'label': 'Source VLAN Name', 'description': 'Source VLAN Name', 'mandatory': False, 'important': False},
                {'value': 'dest_vlan_id', 'label': 'Destination VLAN ID', 'description': 'Destination VLAN ID', 'mandatory': False, 'important': False},
                {'value': 'dest_vlan_name', 'label': 'Destination VLAN Name', 'description': 'Destination VLAN Name', 'mandatory': False, 'important': False},
            ]
            available = fields
        except Exception:
            available = []

        detected_fields = {}
        confidence_scores = {}
        field_priorities = {}
        suggestions = {}

        col_norms = {col: norm(col) for col in columns}
        target_map = {
            'source_ip': ['source_ip', 'sourceaddress', 'src_ip', 'srcaddress', 'source'],
            'dest_ip': ['destination_ip', 'dest_ip', 'destaddress', 'destination'],
            'service': ['service', 'service_port', 'port', 'dest_port', 'service name', 'servicename'],
            'service_port': ['service_port', 'port', 'dest_port'],
            'dest_port': ['dest_port', 'destination port'],
            'service_name': ['service_name', 'service name'],
            'rule_type': ['rule_type', 'type', 'rule type'],
            'action': ['action', 'permit', 'allow', 'deny'],
            'protocol': ['protocol', 'proto'],
            'source_zone': ['source_zone', 'src_zone'],
            'dest_zone': ['dest_zone', 'destination_zone', 'dst_zone'],
            'rule_name': ['name', 'rule_name'],
            'hit_count': ['hit_count', 'hits'],
            'application': ['application', 'app', 'application_name'],
            'source_vlan_id': ['source_vlan_id', 'source vlan id', 'src_vlan', 'src_vlan_id'],
            'source_vlan_name': ['source_vlan_name', 'source vlan name', 'src_vlan_name', 'src_vlan'],
            'dest_vlan_id': ['dest_vlan_id', 'destination vlan id', 'dst_vlan', 'dst_vlan_id'],
            'dest_vlan_name': ['dest_vlan_name', 'destination vlan name', 'dst_vlan_name', 'dst_vlan'],
            'name': ['name', 'object_name', 'group_name', 'object name'],
            'members': ['members', 'items', 'object_items', 'values', 'content'],
            'description': ['description', 'desc'],
            'group_type': ['type', 'group_type']
        }

        for col in columns:
            cn = col_norms.get(col, '')
            best = None
            best_conf = 0.0
            for field, keys in target_map.items():
                for key in keys:
                    if cn == key:
                        best = field; best_conf = 0.95
                        break
                    if key in cn:
                        best = field; best_conf = max(best_conf, 0.6)
                if best:
                    pass
            if best:
                detected_fields[col] = best
                confidence_scores[col] = best_conf
            # suggestions list
            cand = []
            for field in ['source_ip','dest_ip','service_port','action','protocol','source_zone','dest_zone','rule_name','name','members']:
                score = 0.5 if field not in (best or '') else best_conf
                cand.append({'field': field, 'confidence': score, 'reason': 'heuristic'})
            suggestions[col] = cand[:3]
            # priorities
            fp = 'optional'
            if detected_fields.get(col) in ('source_ip','dest_ip','service','service_port','dest_port','service_name','description','group_type'):
                fp = 'important'
            if detected_fields.get(col) in ('action','rule_name','name','members'):
                fp = 'mandatory'
            field_priorities[col] = fp

        mandatory_fields = {'action'}
        important_fields = {'source_ip','dest_ip','service','service_port','dest_port','service_name'}
        
        if file_type == 'objects':
            mandatory_fields = {'name', 'members'}
            important_fields = {'description', 'group_type'}
        elif file_type == 'vlan':
            mandatory_fields = {'vlan_id'}
            important_fields = {'subnet', 'name', 'gateway', 'location'}
            
        present_values = set(detected_fields.values())
        mandatory_missing = sorted(list(mandatory_fields - present_values))
        important_missing = sorted(list(important_fields - present_values))

        return jsonify({
            'success': True,
            'detected_fields': detected_fields,
            'suggestions': suggestions,
            'preview_data': preview_data,
            'confidence_scores': confidence_scores,
            'field_priorities': field_priorities,
            'mandatory_missing': mandatory_missing,
            'important_missing': important_missing,
            'columns': columns,
            'total_rows': total_rows,
            'file_type': file_type,
            'is_text_config': False,
            'format_info': {'filename': filename}
        })
    except Exception as e:
        logger.error(f"Error analyzing file: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        upload = request.files.get('file')
        file_type = request.form.get('file_type') or 'firewall'
        mapping_json = request.form.get('column_mapping')
        if not upload:
            return jsonify({'message': 'No file uploaded'}), 400

        filename = upload.filename or 'uploaded.csv'
        name_lower = (filename or '').lower()
        # Read content
        try:
            content = upload.stream.read()
        except Exception:
            content = upload.read()
        if isinstance(content, bytes):
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except Exception:
                text_content = content.decode('latin-1', errors='ignore')
        else:
            text_content = str(content)

        # Handle text firewall configuration via parser
        if (file_type or '').lower() == 'firewall' and (name_lower.endswith('.txt') or name_lower.endswith('.conf') or ('access-list' in (text_content.lower() if text_content else ''))):
            try:
                temp_fp = os.path.join(_get_uploads_dir(), f"_incoming_{uuid.uuid4().hex}.txt")
                with open(temp_fp, 'w', encoding='utf-8') as fh:
                    fh.write(text_content or '')
                parsed = parser_factory.parse_file(temp_fp, 'firewall', vendor='auto')
                try:
                    os.remove(temp_fp)
                except Exception:
                    pass
                # Cleanup existing object groups for this file
                try:
                    old_groups = db.session.query(ObjectGroup.id).filter(ObjectGroup.source_file == filename).all()
                    old_ids = [g.id for g in old_groups]
                    if old_ids:
                        db.session.query(ObjectGroupMember).filter(ObjectGroupMember.object_group_id.in_(old_ids)).delete(synchronize_session=False)
                        db.session.query(ObjectGroup).filter(ObjectGroup.source_file == filename).delete(synchronize_session=False)
                        db.session.commit()
                except Exception as e:
                    logger.error(f"Error cleaning up old object groups: {e}")
                    db.session.rollback()

                objs = []
                for rec in parsed:
                    rt = rec.get('rule_type')
                    
                    if rt == 'object_group':
                        try:
                            og = ObjectGroup(
                                source_file=filename,
                                file_line_number=rec.get('file_line_number'),
                                name=rec.get('name') or rec.get('acl_name') or rec.get('rule_name') or 'unknown',
                                group_type=rec.get('type') or rec.get('group_type') or 'network',
                                description=rec.get('description'),
                                members=json.dumps(list(rec.get('members', [])))
                            )
                            db.session.add(og)
                            db.session.flush() # Get ID
                            
                            for member_obj in rec.get('members', []):
                                m_type = 'host' # default
                                m_val = ''
                                
                                if isinstance(member_obj, dict):
                                    t = member_obj.get('type')
                                    val = member_obj.get('address')
                                    if t == 'host':
                                        m_type = 'host'
                                        m_val = val
                                    elif t == 'subnet':
                                        m_type = 'subnet'
                                        m_val = val
                                    elif t == 'range':
                                        m_type = 'range'
                                        m_val = val
                                    elif t == 'object_group':
                                        m_type = 'group'
                                        m_val = val
                                    elif t == 'any':
                                        m_type = 'any'
                                        m_val = 'any'
                                    else:
                                        m_type = t or 'unknown'
                                        m_val = val or str(member_obj)
                                else:
                                    member_str = str(member_obj)
                                    m_val = member_str
                                    ms = member_str.lower()
                                    
                                    if ms.startswith('host '):
                                        m_type = 'host'
                                        m_val = member_str[5:].strip()
                                    elif ms.startswith('network-object host '):
                                        m_type = 'host'
                                        m_val = member_str[20:].strip()
                                    elif ms.startswith('network-object '):
                                        m_type = 'subnet'
                                        m_val = member_str[15:].strip()
                                    elif ms.startswith('group-object '):
                                        m_type = 'group'
                                        m_val = member_str[13:].strip()
                                    elif ms.startswith('port-object '):
                                        m_type = 'port'
                                        m_val = member_str[12:].strip()
                                    elif ms.startswith('service-object '):
                                        m_type = 'service'
                                        m_val = member_str[15:].strip()
                                    elif ms.startswith('description '):
                                        continue
                                    elif '/' in ms:
                                        m_type = 'subnet'
                                        m_val = member_str
                                    elif ' ' in ms:
                                        if ms.startswith('range '):
                                            m_type = 'range'
                                            m_val = member_str[6:].strip()
                                        elif ms.startswith('eq '):
                                            m_type = 'port'
                                            m_val = member_str[3:].strip()
                                        elif ms.startswith('lt ') or ms.startswith('gt ') or ms.startswith('neq '):
                                            m_type = 'port'
                                            m_val = member_str.split(' ', 1)[1]
                                        else:
                                            m_type = 'subnet'
                                            m_val = member_str
                                    elif ms.replace('.','').isdigit():
                                        m_type = 'ip'
                                        m_val = member_str
                                    else:
                                        m_type = 'service'
                                        m_val = member_str

                                if m_val:
                                    og_member = ObjectGroupMember(
                                        object_group_id=og.id,
                                        member_type=m_type,
                                        member_value=str(m_val)
                                    )
                                    db.session.add(og_member)
                        except Exception as e:
                            logger.error(f"Error saving object group {rec.get('acl_name')}: {e}")
                        continue

                    if rt not in ('access_list', 'nat'):
                        continue
                    rule = RawFirewallRule(
                        source_file=filename,
                        file_line_number=rec.get('file_line_number'),
                        rule_type=rt,
                        raw_text=rec.get('raw_text') or '',
                        rule_text=rec.get('raw_text') or '',
                        rule_name=rec.get('rule_name') or rec.get('acl_name'),
                        vendor=rec.get('vendor'),
                        acl_name=rec.get('acl_name'),
                        line_number_in_acl=rec.get('line_number_in_acl'),
                        action=rec.get('action'),
                        protocol=rec.get('protocol'),
                        source=rec.get('source'),
                        destination=rec.get('destination'),
                        source_port=rec.get('source_port'),
                        dest_port=rec.get('dest_port'),
                        is_disabled=rec.get('is_disabled', False),
                        source_zone=rec.get('source_zone'),
                        dest_zone=rec.get('dest_zone'),
                        application=rec.get('application'),
                        hit_count=rec.get('hit_count')
                    )
                    # NAT-specific fields
                    try:
                        rule.inside_interface = rec.get('inside_interface')
                        rule.outside_interface = rec.get('outside_interface')
                        rule.nat_id = rec.get('nat_id')
                        rule.translation_type = rec.get('translation_type')
                        rule.real_source = rec.get('real_source')
                        rule.mapped_source = rec.get('mapped_source')
                        rule.real_destination = rec.get('real_destination')
                        rule.mapped_destination = rec.get('mapped_destination')
                    except Exception:
                        pass
                    objs.append(rule)
                if objs:
                    db.session.bulk_save_objects(objs)
                    db.session.commit()
                processed = len(objs)
                # Auto-normalize for this source file
                try:
                    db.session.query(NormalizedRule).filter(NormalizedRule.source_file == filename).delete()
                    db.session.commit()
                    raw_rules_sf = db.session.query(RawFirewallRule).filter(RawFirewallRule.source_file == filename).all()
                    normalized_created = 0
                    for raw in raw_rules_sf:
                        try:
                            service_val = raw.dest_port or ''
                            app_val = raw.application or ''
                            import re as _re
                            tokens = [t.strip() for t in _re.split(r"[;\,\|]+", service_val) if t.strip()] or ([service_val] if service_val else [])
                            protos = []
                            ports = []
                            names = []
                            for t in tokens:
                                tl = t.lower()
                                proto = None
                                port = None
                                name = None
                                if '/' in tl:
                                    parts = tl.split('/', 1)
                                    proto = parts[0].strip()
                                    try:
                                        port = int(parts[1].strip())
                                    except Exception:
                                        port = None
                                else:
                                    m = _re.match(r"^(tcp|udp|icmp|ip)[_\-:\s]?(\d+)$", tl)
                                    if m:
                                        proto = m.group(1)
                                        port = int(m.group(2))
                                    elif tl.isdigit():
                                        port = int(tl)
                                    elif '-' in tl:
                                        segs = tl.split('-', 1)
                                        try:
                                            start_p = int(segs[0])
                                            end_p = int(segs[1])
                                            for p in range(start_p, end_p + 1):
                                                ports.append(str(p))
                                        except Exception:
                                            name = tl
                                    else:
                                        name = tl
                                try:
                                    if name and port is None:
                                        m2 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(name)).first()
                                        if m2:
                                            name = m2.service_name
                                            proto = proto or (m2.protocol.lower() if m2.protocol else None)
                                            port = port or m2.port_number
                                    if port is not None:
                                        q = db.session.query(ServicePortMapping).filter(ServicePortMapping.port_number == port)
                                        if proto:
                                            q = q.filter(ServicePortMapping.protocol.ilike(proto))
                                        m3 = q.first()
                                        if m3:
                                            name = m3.service_name
                                            proto = proto or (m3.protocol.lower() if m3.protocol else None)
                                except Exception:
                                    pass
                                if proto:
                                    protos.append(proto)
                                if port is not None:
                                    ports.append(str(port))
                                if name:
                                    names.append(name)
                            proto_val = raw.protocol or ('; '.join(dict.fromkeys(protos)) if protos else '')
                            service_port_val = '; '.join(dict.fromkeys(ports))
                            resolved_service_name = '; '.join(dict.fromkeys(names)) if names else (service_val or '')
                            action_local = (raw.action or '').strip()
                            if getattr(raw, 'is_disabled', False):
                                toks = [t.strip() for t in re.split(r"[;\,\|\s]+", action_local.lower()) if t.strip()]
                                if 'disabled' not in toks:
                                    action_local = (f"{action_local} disabled").strip() if action_local else 'disabled'
                            norm = NormalizedRule(
                                raw_rule_id=raw.id,
                                source_file=raw.source_file,
                                rule_name=raw.rule_name,
                                rule_type=raw.rule_type,
                                action=action_local,
                                is_disabled=raw.is_disabled,
                                protocol=proto_val,
                                source_zone=(raw.source_zone or ''),
                                source_ip=(raw.source or ''),
                                source_port=(raw.source_port or ''),
                                dest_ip=(raw.destination or ''),
                                dest_port=(service_port_val or raw.dest_port or ''),
                                dest_zone=(raw.dest_zone or ''),
                                application=(app_val or ''),
                                service_name=(resolved_service_name or ''),
                                service_port=(service_port_val or ''),
                                service_protocol=(proto_val or ''),
                                hit_count=raw.hit_count,
                                source_vlan_id=raw.source_vlan_id,
                                source_vlan_name=raw.source_vlan_name,
                                dest_vlan_id=raw.dest_vlan_id,
                                dest_vlan_name=raw.dest_vlan_name,
                                compliance_status='needs_review'
                            )
                            db.session.add(norm)
                            normalized_created += 1
                        except Exception:
                            continue
                    if normalized_created:
                        db.session.commit()
                except Exception as ne:
                    logger.error(f"Auto-normalization failed for {filename}: {ne}")
                response = {'message': 'File uploaded successfully', 'processed_records': processed, 'file_id': filename}
                try:
                    norm_count = db.session.query(NormalizedRule).filter(NormalizedRule.source_file == filename).count()
                    response['normalized_records'] = norm_count
                except Exception:
                    response['normalized_records'] = 0
                return jsonify(response)
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error uploading text firewall config: {e}")
                return jsonify({'message': 'Internal server error'}), 500

        # Parse CSV
        rows = []
        columns = []
        try:
            # Handle BOM
            if text_content.startswith('\ufeff'):
                text_content = text_content[1:]
            
            f = io.StringIO(text_content)
            reader = csv.reader(f)
            rows = list(reader)
            if rows:
                columns = [c.strip() for c in rows[0]]
                logger.info(f"CSV Upload: Detected columns: {columns}")
        except Exception as e:
            logger.error(f"CSV Parsing failed: {e}")
            rows = []
            columns = []

        # Build mapping
        mapping = {}
        if mapping_json:
            try:
                raw_map = json.loads(mapping_json)
                # Handle both formats: column -> field (string) or column -> [field1, field2] (array)
                for col, target in (raw_map or {}).items():
                    try:
                        if isinstance(target, list) and target:
                            # Array format: take the first field
                            mapping[col] = str(target[0])
                        elif isinstance(target, str):
                            # String format: use directly
                            mapping[col] = target
                        # Also handle case where target might be null/undefined
                    except Exception:
                        continue
                logger.info(f"Processed column mapping: {mapping}")
            except Exception as e:
                logger.error(f"Failed to parse column mapping: {e}")
                mapping = {}

        def get_val(row, col_name):
            try:
                idx = columns.index(col_name)
                return row[idx] if idx < len(row) else ''
            except ValueError:
                return ''

        processed = 0
        # Skip header
        data_rows = rows[1:] if len(rows) > 1 else []

        def _infer_protocol(service_val: str, application_val: str):
            try:
                s = (service_val or '').strip().lower()
                if '/' in s:
                    parts = s.split('/', 1)
                    proto = parts[0].strip()
                    if proto in ('tcp', 'udp', 'icmp', 'ip'):
                        return proto
                # numeric port
                try:
                    p = int(s) if s.isdigit() else None
                except Exception:
                    p = None
                from models import ServicePortMapping
                if p is not None:
                    m = db.session.query(ServicePortMapping).filter(ServicePortMapping.port_number == p).first()
                    if m and m.protocol:
                        return m.protocol.lower()
                if s:
                    m2 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(s)).first()
                    if m2 and m2.protocol:
                        return m2.protocol.lower()
                if application_val:
                    m3 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(application_val.strip().lower())).first()
                    if m3 and m3.protocol:
                        return m3.protocol.lower()
            except Exception:
                pass
            return None

        if file_type == 'firewall':
            objs = []
            for r in data_rows:
                # Assemble raw_text from row
                raw_text_parts = []
                for i, col in enumerate(columns):
                    try:
                        raw_text_parts.append(f"{col}: {r[i] if i < len(r) else ''}")
                    except Exception:
                        raw_text_parts.append(f"{col}: ")
                raw_text = '; '.join(raw_text_parts)
                # Map fields
                def map_field(field_name, log=False):
                    # Find column that maps to this field
                    col_for_field = None
                    for col, target in mapping.items():
                        if target == field_name:
                            col_for_field = col; break
                    val = get_val(r, col_for_field) if col_for_field else ''
                    if log:
                        logger.info(f"Mapping '{field_name}' -> Column '{col_for_field}' -> Value '{val}'")
                    return val

                # Log mapping for first row
                should_log = (processed == 0)
                if should_log:
                    logger.info(f"Processing first row. Mapping: {mapping}")
                
                # Unified service value from any of the mapped service-related fields
                service_val = map_field('service', should_log) or map_field('service_port') or map_field('dest_port') or map_field('service_name')
                application_val = map_field('application', should_log)
                protocol_val = map_field('protocol') or ''
                # Auto-detect protocol if not provided
                if not protocol_val:
                    protocol_val = _infer_protocol(service_val, application_val) or ''
                # Derive destination port token if service has proto/port
                dest_port_val = ''
                if service_val:
                    if '/' in service_val:
                        try:
                            dest_port_val = service_val.split('/', 1)[1].strip()
                        except Exception:
                            dest_port_val = service_val
                    else:
                        dest_port_val = service_val
                def _to_int(val):
                    try:
                        v = str(val).strip()
                        if v == '':
                            return None
                        # Remove commas for values like "1,000"
                        v = v.replace(',', '')
                        return int(float(v))
                    except Exception:
                        return None
                hit_count_val = _to_int(map_field('hit_count', should_log))
                if should_log:
                    logger.info(f"Hit Count Raw: '{map_field('hit_count')}' -> Parsed: {hit_count_val}")
                src_vlan_id_val = _to_int(map_field('source_vlan_id'))
                dst_vlan_id_val = _to_int(map_field('dest_vlan_id'))
                src_vlan_name_val = map_field('source_vlan_name')
                dst_vlan_name_val = map_field('dest_vlan_name')
                rule = RawFirewallRule(
                    source_file=filename,
                    rule_type=(map_field('rule_type') or 'universal'),
                    raw_text=raw_text,
                    rule_text=raw_text,
                    rule_name=map_field('rule_name') or get_val(r, 'Name'),
                    vendor=None,
                    action=map_field('action'),
                    protocol=protocol_val,
                    source=map_field('source') or map_field('source_ip'),
                    destination=map_field('destination') or map_field('dest_ip'),
                    source_port=map_field('source_port'),
                    dest_port=dest_port_val,
                    source_zone=map_field('source_zone'),
                    dest_zone=map_field('dest_zone'),
                    application=application_val,
                    hit_count=hit_count_val,
                    source_vlan_id=src_vlan_id_val,
                    source_vlan_name=src_vlan_name_val,
                    dest_vlan_id=dst_vlan_id_val,
                    dest_vlan_name=dst_vlan_name_val
                )
                objs.append(rule)
            if objs:
                db.session.bulk_save_objects(objs)
                db.session.commit()
                processed = len(objs)

                # Auto-normalize for this source file
                try:
                    # Clear existing normalized rules for this source file
                    db.session.query(NormalizedRule).filter(NormalizedRule.source_file == filename).delete()
                    db.session.commit()

                    # Reuse protocol inference helper
                    def _infer_protocol(service_val: str, application_val: str):
                        try:
                            s = (service_val or '').strip().lower()
                            if '/' in s:
                                parts = s.split('/', 1)
                                proto = parts[0].strip()
                                if proto in ('tcp', 'udp', 'icmp', 'ip'):
                                    return proto
                            # numeric port lookup
                            try:
                                p = int(s) if s.isdigit() else None
                            except Exception:
                                p = None
                            from models import ServicePortMapping
                            if p is not None:
                                m = db.session.query(ServicePortMapping).filter(ServicePortMapping.port_number == p).first()
                                if m and m.protocol:
                                    return m.protocol.lower()
                            if s:
                                m2 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(s)).first()
                                if m2 and m2.protocol:
                                    return m2.protocol.lower()
                            if application_val:
                                m3 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(application_val.strip().lower())).first()
                                if m3 and m3.protocol:
                                    return m3.protocol.lower()
                        except Exception:
                            pass
                        return None

                    raw_rules_sf = db.session.query(RawFirewallRule).filter(RawFirewallRule.source_file == filename).all()
                    normalized_created = 0
                    for raw in raw_rules_sf:
                        try:
                            service_val = raw.dest_port or ''
                            app_val = raw.application or ''
                            # Parse multiple service tokens
                            import re
                            tokens = [t.strip() for t in re.split(r"[;\,\|]+", service_val) if t.strip()] or ([service_val] if service_val else [])
                            protos = []
                            ports = []
                            names = []
                            from models import ServicePortMapping
                            for t in tokens:
                                tl = t.lower()
                                proto = None
                                port = None
                                name = None
                                if '/' in tl:
                                    parts = tl.split('/', 1)
                                    proto = parts[0].strip()
                                    try:
                                        port = int(parts[1].strip())
                                    except Exception:
                                        port = None
                                else:
                                    m = re.match(r"^(tcp|udp|icmp|ip)[_\-:\s]?(\d+)$", tl)
                                    if m:
                                        proto = m.group(1)
                                        port = int(m.group(2))
                                    elif tl.isdigit():
                                        port = int(tl)
                                    else:
                                        name = tl
                                try:
                                    if name and port is None:
                                        m2 = db.session.query(ServicePortMapping).filter(ServicePortMapping.service_name.ilike(name)).first()
                                        if m2:
                                            name = m2.service_name
                                            proto = proto or (m2.protocol.lower() if m2.protocol else None)
                                            port = port or m2.port_number
                                    if port is not None:
                                        q = db.session.query(ServicePortMapping).filter(ServicePortMapping.port_number == port)
                                        if proto:
                                            q = q.filter(ServicePortMapping.protocol.ilike(proto))
                                        m3 = q.first()
                                        if m3:
                                            name = m3.service_name
                                            proto = proto or (m3.protocol.lower() if m3.protocol else None)
                                except Exception:
                                    pass
                                if proto:
                                    protos.append(proto)
                                if port is not None:
                                    ports.append(str(port))
                                if name:
                                    names.append(name)
                            # Compose normalized values
                            proto_val = raw.protocol or ('; '.join(dict.fromkeys(protos)) if protos else (_infer_protocol(service_val, app_val) or ''))
                            service_port_val = '; '.join(dict.fromkeys(ports))
                            resolved_service_name = '; '.join(dict.fromkeys(names)) if names else (service_val or '')
                            norm = NormalizedRule(
                                raw_rule_id=raw.id,
                                source_file=raw.source_file,
                                rule_name=raw.rule_name,
                                rule_type=raw.rule_type,
                                action=(raw.action or ''),
                                protocol=proto_val,
                                source_zone=(raw.source_zone or ''),
                                source_ip=(raw.source or ''),
                                source_port=(raw.source_port or ''),
                                dest_ip=(raw.destination or ''),
                                dest_port=(service_port_val or raw.dest_port or ''),
                                dest_zone=(raw.dest_zone or ''),
                                application=(app_val or ''),
                                service_name=(resolved_service_name or ''),
                                service_port=(service_port_val or ''),
                                service_protocol=(proto_val or ''),
                                hit_count=raw.hit_count,
                                source_vlan_id=raw.source_vlan_id,
                                source_vlan_name=raw.source_vlan_name,
                                dest_vlan_id=raw.dest_vlan_id,
                                dest_vlan_name=raw.dest_vlan_name,
                                compliance_status='needs_review'
                            )
                            db.session.add(norm)
                            normalized_created += 1
                        except Exception:
                            continue
                    if normalized_created:
                        db.session.commit()
                except Exception as ne:
                    logger.error(f"Auto-normalization failed for {filename}: {ne}")

        elif file_type == 'cmdb':
            objs = []
            for r in data_rows:
                def map_field(field_name):
                    col_for_field = None
                    for col, target in mapping.items():
                        if target == field_name:
                            col_for_field = col; break
                    return get_val(r, col_for_field) if col_for_field else ''
                add = {}
                for i, col in enumerate(columns):
                    add[col] = r[i] if i < len(r) else ''
                # normalize PCI DSS category to canonical key if present under variants
                try:
                    lk = {str(k).lower(): k for k in add.keys()}
                    variants = ['pcidss_asset_category','pci dss category','pcidss category','pcidsscategory','pci_category','pci dss cat']
                    cat_val = None
                    for v in variants:
                        if v in lk:
                            cat_val = add.get(lk[v]); break
                    if cat_val is not None:
                        val = str(cat_val).strip().upper()
                        if val.startswith('CATEGORY '):
                            val = val.split(' ', 1)[1]
                        add['pcidss_asset_category'] = val
                except Exception:
                    pass
                asset = CMDBAsset(
                    source_file=filename,
                    hostname=map_field('hostname') or get_val(r, 'Hostname'),
                    ip_address=map_field('ip_address') or get_val(r, 'IP Address'),
                    owner=map_field('owner'),
                    department=map_field('department'),
                    operating_system=map_field('operating_system'),
                    location=map_field('location'),
                    environment=map_field('environment'),
                    business_unit=map_field('business_unit'),
                    status='active',
                    additional_data=json.dumps(add)
                )
                objs.append(asset)
            if objs:
                db.session.bulk_save_objects(objs)
                db.session.commit()
                processed = len(objs)

        elif file_type == 'vlan':
            objs = []
            for r in data_rows:
                def map_field(field_name):
                    col_for_field = None
                    for col, target in mapping.items():
                        if target == field_name:
                            col_for_field = col; break
                    return get_val(r, col_for_field) if col_for_field else ''
                vlan = VLANNetwork(
                    source_file=filename,
                    vlan_id=int(map_field('vlan_id') or get_val(r, 'VLAN ID') or '0'),
                    name=map_field('name') or get_val(r, 'Name'),
                    subnet=map_field('subnet') or get_val(r, 'Subnet'),
                    gateway=map_field('gateway') or get_val(r, 'Gateway'),
                    description=map_field('description'),
                    location=map_field('location'),
                    status='active'
                )
                objs.append(vlan)
            if objs:
                db.session.bulk_save_objects(objs)
                db.session.commit()
                processed = len(objs)
        else:
            # objects or unknown: accept and no-op
            processed = 0

        # Include normalized count for firewall uploads
        response = {'message': 'File uploaded successfully', 'processed_records': processed, 'file_id': filename}
        if file_type == 'firewall':
            try:
                norm_count = db.session.query(NormalizedRule).filter(NormalizedRule.source_file == filename).count()
                response['normalized_records'] = norm_count
            except Exception:
                response['normalized_records'] = 0
        return jsonify(response)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error uploading file: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/normalize-rules', methods=['POST'])
def normalize_rules():
    try:
        payload = request.get_json() or {}
        source_file = payload.get('source_file')
        clear_existing = bool(payload.get('clear_existing'))
        mode = (payload.get('mode') or 'one_to_one').lower()
        if not source_file:
            return jsonify({'error': 'source_file is required'}), 400

        # Import the proper rule normalizer
        from rule_normalizer import normalize_firewall_rules
        
        # Use the proper rule normalizer that performs IP-to-VLAN matching
        results = normalize_firewall_rules(
            source_file=source_file,
            clear_existing=clear_existing,
            expand_services=(mode == 'expand_services'),
            group_by_remark=(mode == 'group_by_remark')
        )
        
        return jsonify(results)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error normalizing rules: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/normalized-rules/bulk-delete', methods=['DELETE'])
def bulk_delete_normalized_rules():
    try:
        data = request.get_json() or {}
        if data.get('delete_all'):
            db.session.query(NormalizedRule).delete()
            db.session.commit()
            return jsonify({'success': True})
        source_file = data.get('source_file')
        if source_file:
            db.session.query(NormalizedRule).filter(NormalizedRule.source_file == source_file).delete()
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting normalized rules: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/export/excel/<review_session_id>', methods=['GET'])
def export_review_results(review_session_id):
    try:
        excel_bytes = generate_excel_export(review_session_id)
        return send_file(
            io.BytesIO(excel_bytes),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'review_export_{review_session_id}.xlsx'
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        if "No results found" in str(e):
             return jsonify({'error': str(e)}), 404
        logger.error(f"Export failed: {e}")
        return jsonify({'error': 'Export failed'}), 500


@app.route('/api/vlans/import', methods=['POST'])
def import_vlans():
    try:
        file = request.files.get('file')
        mapping_json = request.form.get('mapping')
        if not file or not mapping_json:
            return jsonify({'error': 'Missing file or mapping'}), 400
        
        mapping = json.loads(mapping_json)
        
        # Invert mapping: Frontend sends { 'CSV_Col': ['Internal_Field'] }
        # Backend needs { 'Internal_Field': ['CSV_Col'] }
        internal_mapping = {}
        for csv_col, internal_fields in mapping.items():
            # Strip whitespace from CSV column name to match stripped headers
            csv_col = csv_col.strip()
            
            if isinstance(internal_fields, list):
                for field in internal_fields:
                    if field not in internal_mapping:
                        internal_mapping[field] = []
                    internal_mapping[field].append(csv_col)
            else:
                # Handle legacy/simple mapping { 'CSV_Col': 'Internal_Field' }
                field = internal_fields
                if field not in internal_mapping:
                    internal_mapping[field] = []
                internal_mapping[field].append(csv_col)
        mapping = internal_mapping
        
        # Read file content
        content = file.read()
        try:
            text_content = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            text_content = content.decode('latin-1')
        
        # Filter out comment lines (starting with #)
        lines = [line for line in text_content.splitlines() if line.strip() and not line.strip().startswith('#')]
        
        if not lines:
             return jsonify({'error': 'File is empty or contains only comments'}), 400

        stream = io.StringIO('\n'.join(lines), newline=None)
        reader = csv.DictReader(stream)
        
        # Normalize headers (strip whitespace)
        if reader.fieldnames:
            reader.fieldnames = [h.strip() for h in reader.fieldnames]
        
        created_count = 0
        errors = []
        
        for i, row in enumerate(reader):
            try:
                # Map fields
                vlan_data = {}
                for field, cols in mapping.items():
                    val = None
                    if isinstance(cols, list):
                        for col in cols:
                            if col in row and row[col]:
                                val = row[col]
                                break
                    else:
                        if cols in row:
                            val = row[cols]
                    
                    if val is not None:
                        vlan_data[field] = val.strip()
                
                # Create VLAN
                if 'vlan_id' in vlan_data:
                    # Check if exists
                    try:
                        vid = int(vlan_data['vlan_id'])
                    except ValueError:
                        continue
                        
                    existing = VLANNetwork.query.filter_by(vlan_id=vid).first()
                    if existing:
                        # Update existing
                        for k, v in vlan_data.items():
                            if k != 'vlan_id' and hasattr(existing, k):
                                setattr(existing, k, v)
                    else:
                        vlan = VLANNetwork(
                            vlan_id=vid,
                            name=vlan_data.get('name', ''),
                            subnet=vlan_data.get('subnet', ''),
                            gateway=vlan_data.get('gateway', ''),
                            description=vlan_data.get('description', ''),
                            location=vlan_data.get('location', ''),
                            source_file=file.filename,
                            status='active',
                            vlan_type='access'
                        )
                        db.session.add(vlan)
                    created_count += 1
            except Exception as e:
                errors.append(f"Row {i+1}: {str(e)}")
        
        db.session.commit()
        return jsonify({'success': True, 'count': created_count, 'errors': errors})

    except Exception as e:
        logger.error(f"Error importing VLANs: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/object-groups/import', methods=['POST'])
def import_object_groups():
    try:
        file = request.files.get('file')
        mapping_json = request.form.get('mapping')
        if not file or not mapping_json:
            return jsonify({'error': 'Missing file or mapping'}), 400
        
        mapping = json.loads(mapping_json)

        # Invert mapping: Frontend sends { 'CSV_Col': ['Internal_Field'] }
        # Backend needs { 'Internal_Field': ['CSV_Col'] }
        internal_mapping = {}
        for csv_col, internal_fields in mapping.items():
            if isinstance(internal_fields, list):
                for field in internal_fields:
                    if field not in internal_mapping:
                        internal_mapping[field] = []
                    internal_mapping[field].append(csv_col)
            else:
                # Handle legacy/simple mapping { 'CSV_Col': 'Internal_Field' }
                field = internal_fields
                if field not in internal_mapping:
                    internal_mapping[field] = []
                internal_mapping[field].append(csv_col)
        mapping = internal_mapping
        
        # Read file content
        content = file.read()
        try:
            text_content = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            text_content = content.decode('latin-1')
        
        # Filter out comment lines (starting with #)
        lines = [line for line in text_content.splitlines() if line.strip() and not line.strip().startswith('#')]
        
        if not lines:
             return jsonify({'error': 'File is empty or contains only comments'}), 400

        stream = io.StringIO('\n'.join(lines), newline=None)
        reader = csv.DictReader(stream)
        
        # Normalize headers (strip whitespace)
        if reader.fieldnames:
            reader.fieldnames = [h.strip() for h in reader.fieldnames]
        
        logger.info(f"Importing Object Groups. Headers: {reader.fieldnames}")
        logger.info(f"Mapping (Internal -> CSV): {mapping}")
 
        created_count = 0
        errors = []
        
        for i, row in enumerate(reader):
            try:
                # Map fields
                group_data = {}
                for field, cols in mapping.items():
                    val = None
                    if isinstance(cols, list):
                        for col in cols:
                            if col in row and row[col]:
                                val = row[col]
                                break
                    else:
                        if cols in row:
                            val = row[cols]
                    
                    if val is not None:
                        group_data[field] = val.strip()
                
                name = group_data.get('name')
                members_str = group_data.get('members', '')
                
                # Debug logging for members extraction
                logger.info(f"Row {i} - Name: {name}, Members Raw: '{members_str}'")
                if not name:
                    logger.warning(f"Row {i}: Skipping because name is empty. Raw Row: {row}")
                    continue
                
                # Determine type based on members
                # Handle various delimiters: newlines, semicolons, commas, spaces
                # Replace explicit delimiters with space, then split by whitespace
                temp_str = re.sub(r'[;\n,]', ' ', members_str)
                members = [m.strip() for m in temp_str.split() if m.strip()]
                
                logger.info(f"Row {i} - Extracted Members: {members}")

                group_type = group_data.get('group_type', 'network')

                group_type = group_data.get('group_type', 'network')
                # Simple heuristic if type not provided
                if 'group_type' not in group_data and members:
                    # Check if first member looks like IP
                    if re.match(r'^\d{1,3}\.', members[0]):
                        group_type = 'network'
                    else:
                        group_type = 'service'

                existing = ObjectGroup.query.filter_by(name=name).first()
                if existing:
                    group = existing
                    group.description = group_data.get('description', group.description)
                else:
                    group = ObjectGroup(
                        name=name,
                        group_type=group_type,
                        description=group_data.get('description', ''),
                        status='active',
                        source_file=file.filename,
                        vendor='generic'
                    )
                    db.session.add(group)
                    db.session.flush() # Get ID
                
                # Dedup input members
                members = list(set(members))

                # Update members JSON
                existing_members_list = []
                if group.members:
                    try:
                        existing_members_list = json.loads(group.members)
                    except:
                        pass
                
                # Merge lists (avoid duplicates)
                merged_members = list(set(existing_members_list + members))
                group.members = json.dumps(merged_members)

                # Add members to ObjectGroupMember table
                existing_db_members = ObjectGroupMember.query.filter_by(object_group_id=group.id).all()
                existing_db_values = {m.member_value for m in existing_db_members}
                
                for m_val in members:
                    if m_val not in existing_db_values:
                        # Determine member type
                        m_type = 'ip'
                        if group_type == 'service':
                            m_type = 'port' # Simplified
                        
                        member = ObjectGroupMember(
                            object_group_id=group.id,
                            member_type=m_type,
                            member_value=m_val,
                            description='Imported'
                        )
                        db.session.add(member)
                        existing_db_values.add(m_val)
                
                created_count += 1
            except Exception as e:
                errors.append(f"Row {i+1}: {str(e)}")
        
        db.session.commit()
        return jsonify({'success': True, 'count': created_count, 'errors': errors})

    except Exception as e:
        logger.error(f"Error importing object groups: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/import-templates/vlan-object-group', methods=['GET'])
def download_vlan_object_template():
    try:
        # Create a ZIP file containing both templates or just a CSV with instructions
        # For simplicity, let's return a CSV that works for both if the user fills appropriate columns,
        # or better, create two separate sheets if we supported Excel, but for CSV let's return a combined structure or just one.
        # The user asked for "a template", implying one download.
        # Let's create a CSV with columns for both VLAN and Object Group
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['# Template for VLAN and Object Group Import'])
        writer.writerow(['# Fill VLAN columns for VLAN import, Object columns for Object Group import'])
        writer.writerow(['# VLAN Columns:', 'vlan_id', 'name', 'subnet', 'gateway', 'location', 'description'])
        writer.writerow(['# Object Columns:', 'name', 'members', 'description', 'group_type'])
        writer.writerow([])
        writer.writerow(['vlan_id', 'name', 'subnet', 'gateway', 'location', 'description', 'members', 'group_type'])
        writer.writerow(['10', 'Data_VLAN', '192.168.10.0/24', '192.168.10.1', 'DC1', 'Server VLAN', '', ''])
        writer.writerow(['', 'Web_Servers', '', '', '', 'Web Server Group', '192.168.10.5\n192.168.10.6', 'network'])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='import_template.csv'
        )
    except Exception as e:
        logger.error(f"Error downloading template: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Ensure tables exist
        db.create_all()
        # Ensure 'logic' column exists on compliance_rules for older DBs
        try:
            cols = db.session.execute(text("PRAGMA table_info(compliance_rules)")).fetchall()
            col_names = {row[1] for row in cols}  # row[1] is 'name'
            if 'logic' not in col_names:
                db.session.execute(text("ALTER TABLE compliance_rules ADD COLUMN logic VARCHAR(10)"))
                db.session.commit()
        except Exception as e:
            logger.warning(f"Schema check failed: {e}")
    app.run(debug=True, port=5001)
