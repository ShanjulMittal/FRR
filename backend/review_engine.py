"""
Review execution engine for running compliance checks against normalized rules
"""
import uuid
import json
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from models import db, NormalizedRule, ComplianceRule, ReviewProfile, ReviewResult, ProfileRuleLink
from compliance_engine import ComplianceEngine

def run_review_process(profile_id):
    """
    Execute the review process for a given profile
    
    Args:
        profile_id (int): ID of the review profile to execute
        
    Returns:
        dict: Review execution results with session_id and summary statistics
    """
    try:
        # Generate unique session ID for this review run
        review_session_id = str(uuid.uuid4())
        
        # Get the review profile
        profile = ReviewProfile.query.get(profile_id)
        if not profile:
            raise ValueError(f"Review profile with ID {profile_id} not found")
        
        # Get all compliance rules for this profile
        compliance_rules = db.session.query(ComplianceRule)\
            .join(ProfileRuleLink)\
            .filter(ProfileRuleLink.profile_id == profile_id)\
            .filter(ComplianceRule.is_active == True)\
            .all()
        
        if not compliance_rules:
            raise ValueError(f"No active compliance rules found for profile {profile.profile_name}")
        
        # Get all normalized rules to check
        normalized_rules = NormalizedRule.query.filter(NormalizedRule.is_deleted == False).all()
        
        if not normalized_rules:
            raise ValueError("No normalized rules found to check")
        
        # Statistics tracking
        stats = {
            'total_rules_scanned': len(normalized_rules),
            'total_compliance_checks': len(compliance_rules),
            'compliant_count': 0,
            'non_compliant_count': 0,
            'findings_by_rule': {},
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        }
        
        # Initialize compliance engine
        compliance_engine = ComplianceEngine()
        
        # Process each normalized rule against each compliance rule
        for normalized_rule in normalized_rules:
            for compliance_rule in compliance_rules:
                try:
                    # Treat explicit deny/block/drop actions as compliant (tokenized)
                    action_val = str(getattr(normalized_rule, 'action', '') or '').strip().lower()
                    action_tokens = [t.strip() for t in re.split(r"[;\,\|\s]+", action_val) if t.strip()]
                    if any(t in ('deny', 'block', 'drop') for t in action_tokens):
                        status = 'compliant'
                        failed_checks = []
                    else:
                        # Run the compliance check
                        result = compliance_engine.evaluate_rule_against_compliance(
                            normalized_rule, 
                            compliance_rule
                        )
                        # Determine status based on evaluation result
                        status = 'non_compliant' if not result.get('compliant', True) else 'compliant'
                        # Prepare failed checks information
                        failed_checks = []
                        if status == 'non_compliant':
                            if compliance_rule.operator == 'composite' and result.get('violation_details'):
                                try:
                                    details = json.loads(result.get('violation_details'))
                                    failed_checks = details if isinstance(details, list) else [details]
                                except Exception:
                                    failed_checks.append({
                                        'rule_name': compliance_rule.rule_name,
                                        'operator': 'composite',
                                        'description': 'Composite rule failure'
                                    })
                            else:
                                failed_checks.append({
                                    'rule_name': compliance_rule.rule_name,
                                    'field_checked': compliance_rule.field_to_check,
                                    'operator': compliance_rule.operator,
                                    'expected_value': compliance_rule.value,
                                    'actual_value': result.get('field_value', ''),
                                    'description': compliance_rule.description
                                })
                    
                    # Create review result record
                    review_result = ReviewResult(
                        normalized_rule_id=normalized_rule.id,
                        compliance_rule_id=compliance_rule.id,
                        profile_id=profile_id,
                        review_session_id=review_session_id,
                        status=status,
                        failed_checks=json.dumps(failed_checks) if failed_checks else None,
                        severity=compliance_rule.severity if status == 'non_compliant' else None,
                        notes=f"Automated check performed on {datetime.now(ZoneInfo('Asia/Kolkata')).isoformat()}"
                    )
                    
                    db.session.add(review_result)
                    
                    # Update statistics
                    if status == 'compliant':
                        stats['compliant_count'] += 1
                    else:
                        stats['non_compliant_count'] += 1
                        
                        # Track findings by compliance rule
                        rule_name = compliance_rule.rule_name
                        if rule_name not in stats['findings_by_rule']:
                            stats['findings_by_rule'][rule_name] = 0
                        stats['findings_by_rule'][rule_name] += 1
                        
                        # Track severity breakdown
                        if compliance_rule.severity in stats['severity_breakdown']:
                            stats['severity_breakdown'][compliance_rule.severity] += 1
                
                except Exception as e:
                    # Log individual check failures but continue processing
                    print(f"Error checking rule {normalized_rule.id} against compliance rule {compliance_rule.id}: {str(e)}")
                    continue
        
        # Commit all results to database
        db.session.commit()
        
        # Calculate additional statistics
        total_checks = stats['compliant_count'] + stats['non_compliant_count']
        compliance_percentage = (stats['compliant_count'] / total_checks * 100) if total_checks > 0 else 0
        
        return {
            'success': True,
            'review_session_id': review_session_id,
            'profile_name': profile.profile_name,
            'execution_time': datetime.utcnow().isoformat(),
            'statistics': {
                **stats,
                'total_checks_performed': total_checks,
                'compliance_percentage': round(compliance_percentage, 2)
            }
        }
        
    except Exception as e:
        # Rollback any partial changes
        db.session.rollback()
        return {
            'success': False,
            'error': str(e),
            'review_session_id': None
        }

def get_review_results(review_session_id=None, profile_id=None, limit=None, offset=None, rule_name=None, status=None):
    """
    Retrieve review results with optional filtering
    
    Args:
        review_session_id (str, optional): Filter by specific review session
        profile_id (int, optional): Filter by profile ID
        limit (int, optional): Limit number of results
        offset (int, optional): Offset for pagination
        
    Returns:
        dict: Review results with metadata
    """
    try:
        query = db.session.query(ReviewResult)\
            .join(NormalizedRule)\
            .join(ComplianceRule)\
            .join(ReviewProfile)
        
        # Apply filters
        if review_session_id:
            query = query.filter(ReviewResult.review_session_id == review_session_id)
        
        if profile_id:
            query = query.filter(ReviewResult.profile_id == profile_id)

        if status:
            query = query.filter(ReviewResult.status == status)

        if rule_name:
            query = query.filter(ComplianceRule.rule_name == rule_name)
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply pagination
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)
        
        results = query.all()
        
        # Convert to dictionaries with additional context
        formatted_results = []
        for result in results:
            result_dict = result.to_dict()
            
            # Add normalized rule context (include custom fields and append VPN to destination for display)
            custom_fields_data = getattr(result.normalized_rule, 'custom_fields_data', None)
            vpn_value = None
            try:
                if custom_fields_data:
                    cf_obj = json.loads(custom_fields_data) if isinstance(custom_fields_data, str) else custom_fields_data
                    if isinstance(cf_obj, dict):
                        for k in ('vpn', 'VPN', 'Vpn'):
                            v = cf_obj.get(k)
                            if isinstance(v, str) and v.strip():
                                vpn_value = v.strip()
                                break
            except Exception:
                vpn_value = None

            dest_ip_value = result.normalized_rule.dest_ip
            if vpn_value:
                if dest_ip_value:
                    dest_ip_value = f"{dest_ip_value}; VPN: {vpn_value}"
                else:
                    dest_ip_value = f"VPN: {vpn_value}"

            result_dict['normalized_rule'] = {
                'id': result.normalized_rule.id,
                'source_file': result.normalized_rule.source_file,
                'rule_name': result.normalized_rule.rule_name,
                'action': result.normalized_rule.action,
                'protocol': result.normalized_rule.protocol,
                'source_ip': result.normalized_rule.source_ip,
                'dest_ip': dest_ip_value,
                'service_name': result.normalized_rule.service_name,
                'service_protocol': getattr(result.normalized_rule, 'service_protocol', None),
                'raw_text': getattr(getattr(result.normalized_rule, 'raw_rule', None), 'raw_text', None),
                'rule_text': getattr(getattr(result.normalized_rule, 'raw_rule', None), 'rule_text', None),
                'custom_fields_data': custom_fields_data
            }
            
            # Add raw rule full context with column names
            try:
                raw_rule_obj = getattr(result.normalized_rule, 'raw_rule', None)
                result_dict['raw_rule'] = raw_rule_obj.to_dict() if raw_rule_obj and hasattr(raw_rule_obj, 'to_dict') else None
            except Exception:
                result_dict['raw_rule'] = None
            
            # Add compliance rule context
            result_dict['compliance_rule'] = {
                'id': result.compliance_rule.id,
                'rule_name': result.compliance_rule.rule_name,
                'description': result.compliance_rule.description,
                'severity': result.compliance_rule.severity,
                'field_to_check': result.compliance_rule.field_to_check,
                'operator': result.compliance_rule.operator,
                'value': result.compliance_rule.value
            }
            
            # Add profile context
            result_dict['profile'] = {
                'id': result.profile.id,
                'profile_name': result.profile.profile_name,
                'compliance_framework': result.profile.compliance_framework
            }
            
            formatted_results.append(result_dict)
        
        return {
            'success': True,
            'results': formatted_results,
            'total_count': total_count,
            'returned_count': len(formatted_results)
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'results': [],
            'total_count': 0,
            'returned_count': 0
        }

def get_review_summary(review_session_id):
    """
    Get summary statistics for a specific review session
    
    Args:
        review_session_id (str): Review session ID
        
    Returns:
        dict: Summary statistics
    """
    try:
        # Get all results for this session
        results = ReviewResult.query.filter(
            ReviewResult.review_session_id == review_session_id
        ).all()
        
        if not results:
            return {
                'success': False,
                'error': 'No results found for this review session'
            }
        
        # Calculate summary statistics
        total_checks = len(results)
        compliant_count = len([r for r in results if r.status == 'compliant'])
        non_compliant_count = len([r for r in results if r.status == 'non_compliant'])
        
        findings_by_rule = {}
        severity_breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        checks_by_rule = {}
        
        for result in results:
            rule_name = result.compliance_rule.rule_name
            if rule_name not in checks_by_rule:
                checks_by_rule[rule_name] = {
                    'name': rule_name,
                    'description': result.compliance_rule.description,
                    'severity': result.compliance_rule.severity,
                    'compliant': 0,
                    'non_compliant': 0,
                    'total': 0
                }
            checks = checks_by_rule[rule_name]
            checks['total'] += 1
            if result.status == 'compliant':
                checks['compliant'] += 1
            else:
                checks['non_compliant'] += 1
                if rule_name not in findings_by_rule:
                    findings_by_rule[rule_name] = 0
                findings_by_rule[rule_name] += 1
                if result.severity in severity_breakdown:
                    severity_breakdown[result.severity] += 1
        
        # Get unique normalized rules scanned
        unique_rules_scanned = len(set(r.normalized_rule_id for r in results))
        
        # Get profile information
        profile = results[0].profile if results else None
        
        compliance_percentage = (compliant_count / total_checks * 100) if total_checks > 0 else 0
        
        return {
            'success': True,
            'review_session_id': review_session_id,
            'profile': {
                'id': profile.id if profile else None,
                'name': profile.profile_name if profile else None,
                'framework': profile.compliance_framework if profile else None
            },
            'execution_time': results[0].checked_at.isoformat() if results else None,
            'statistics': {
                'total_rules_scanned': unique_rules_scanned,
                'total_checks_performed': total_checks,
                'compliant_count': compliant_count,
                'non_compliant_count': non_compliant_count,
                'compliance_percentage': round(compliance_percentage, 2),
                'findings_by_rule': findings_by_rule,
                'severity_breakdown': severity_breakdown,
                'checks_by_rule': checks_by_rule
            }
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }