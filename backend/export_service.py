import pandas as pd
import io
import json
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional
from models import db, ReviewResult, NormalizedRule, ComplianceRule, ReviewProfile, CMDBAsset
from sqlalchemy.orm import joinedload

def generate_excel_export(review_session_id: str, include_compliant: Optional[bool] = None) -> bytes:
    """
    Generate Excel export with compliance status columns for a review session.
    Returns the Excel file as bytes.
    """
    try:
        # Get review results with all related data
        # Optimize: Eager load raw_rule to avoid N+1 queries
        results = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.normalized_rule).joinedload(NormalizedRule.raw_rule),
            joinedload(ReviewResult.compliance_rule),
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id).all()
        
        if not results:
            raise ValueError("No results found for the specified review session")
        if include_compliant is not None and include_compliant is False:
            results = [r for r in results if r.status == 'non_compliant']
        
        # Optimization: Pre-fetch CMDB PCI data for O(1) lookup
        # This avoids executing SQL queries for every single row in the loop
        assets = db.session.query(CMDBAsset.ip_address, CMDBAsset.hostname, CMDBAsset.additional_data).all()
        ip_pci_map = {}
        host_pci_map = {}
        
        for ip, hostname, data in assets:
            if not data:
                continue
            try:
                d = json.loads(data)
                cat = d.get('pcidss_asset_category')
                if cat:
                    if ip:
                        ip_pci_map[ip] = cat
                    if hostname:
                        host_pci_map[hostname.lower()] = cat
            except:
                pass

        def get_pci_categories(ip_field: str, hostname_field: str = None) -> str:
            cats = set()
            # Check IPs
            if ip_field:
                # Split by common delimiters
                tokens = [t.strip() for t in ip_field.replace(';', ',').split(',')]
                for t in tokens:
                    # Clean up token (remove 'host ', etc if present)
                    t_clean = t.lower().replace('host ', '').strip()
                    if t_clean in ip_pci_map:
                        cats.add(ip_pci_map[t_clean])
            # Check Hostname
            if hostname_field:
                h_clean = hostname_field.lower().strip()
                if h_clean in host_pci_map:
                    cats.add(host_pci_map[h_clean])
            return ', '.join(sorted(list(cats)))

        # Group results by source file
        files_data = {}
        
        for result in results:
            source_file = result.normalized_rule.source_file
            if source_file not in files_data:
                files_data[source_file] = []
            
            # Create row data with compliance information
            nr = result.normalized_rule
            safe = lambda name: getattr(nr, name, '')
            
            # Use optimized lookup instead of nr.to_dict()
            src_cats = get_pci_categories(nr.source_ip, nr.source_hostname)
            dst_cats = get_pci_categories(nr.dest_ip, nr.dest_hostname)

            row_data = {
                'Rule_ID': safe('id'),
                'Rule_Name': safe('rule_name'),
                'Line_Number': safe('line_number'),
                'Action': safe('action'),
                'Protocol': safe('protocol'),
                'Source_IP': safe('source_ip'),
                'Source_Zone': safe('source_zone'),
                'Source_Port': safe('source_port'),
                'Dest_IP': safe('dest_ip'),
                'Dest_Zone': safe('dest_zone'),
                'Dest_Port': safe('dest_port'),
                'Service_Name': safe('service_name'),
                'Source_VLAN': safe('source_vlan'),
                'Dest_VLAN': safe('dest_vlan'),
                'Interface': safe('interface'),
                'Direction': safe('direction'),
                'Logging': safe('logging'),
                'Description': safe('description'),
                'Original_Rule': safe('original_rule'),
                'Raw_Text': safe('raw_text'),
                'Raw_Rule_Text': '',
                'Source_PCI_DSS_Categories': src_cats,
                'Dest_PCI_DSS_Categories': dst_cats,
                # New compliance columns
                'Compliance_Status': result.status.replace('_', ' ').title(),
                'Failed_Checks': len(result.failed_checks) if result.failed_checks else 0,
                'Severity': result.severity,
                'Compliance_Rule_Name': result.compliance_rule.rule_name if result.compliance_rule else '',
                'Check_Description': result.compliance_rule.description if result.compliance_rule else '',
                'Field_Checked': '',
                'Operator': '',
                'Expected_Value': '',
                'Actual_Value': '',
                'Non_Compliance_Type': result.compliance_rule.rule_name if result.compliance_rule else '',
                'Findings_Details': '',
                'Notes': result.notes or '',
                'Checked_At': result.checked_at.strftime('%Y-%m-%d %H:%M:%S') if result.checked_at else ''
            }
            # Add friendly explanation based on first failed check
            try:
                checks = json.loads(result.failed_checks) if isinstance(result.failed_checks, str) else (result.failed_checks or [])
                if checks:
                    first = checks[0] if isinstance(checks[0], dict) else {}
                    op = (first.get('operator') or '').lower()
                    expected = first.get('expected_value') or ''
                    actual = first.get('actual_value') or ''
                    field_checked = first.get('field_checked') or ''
                    row_data['Field_Checked'] = field_checked
                    row_data['Operator'] = op
                    row_data['Expected_Value'] = expected
                    row_data['Actual_Value'] = actual
                    def _meaning(o,e,a):
                        m = {
                          'equals': f"should equal '{e}' but is '{a}'",
                          'not_equals': f"should not equal '{e}' but is '{a}'",
                          'contains': f"should include '{e}' but is '{a}'",
                          'not_contains': f"should not include '{e}' but is '{a}'",
                          'in_list': f"should be one of '{e}' but is '{a}'",
                          'not_in_list': f"should not be any of '{e}' but is '{a}'",
                          'regex_match': f"should match pattern '{e}' but is '{a}'",
                          'not_regex_match': f"should not match pattern '{e}' but is '{a}'",
                          'starts_with': f"should start with '{e}' but is '{a}'",
                          'ends_with': f"should end with '{e}' but is '{a}'",
                          'is_empty': f"should be empty but is '{a}'",
                          'is_not_empty': f"should not be empty",
                          'greater_than': f"should be > '{e}' but is '{a}'",
                          'greater_than_or_equal': f"should be >= '{e}' but is '{a}'",
                          'less_than': f"should be < '{e}' but is '{a}'",
                          'less_than_or_equal': f"should be <= '{e}' but is '{a}'",
                          'composite': "did not satisfy combined conditions"
                        }
                        return m.get(o, f"expected '{e}' using '{o}', actual '{a}'")
                    row_data['Plain_Explanation'] = _meaning(op, expected, actual)
                    row_data['Why_It_Matters'] = f"Severity {result.severity or ''}: higher severity needs faster fix."
                    try:
                        row_data['Findings_Details'] = json.dumps(checks)
                    except Exception:
                        row_data['Findings_Details'] = ''
                else:
                    row_data['Plain_Explanation'] = ''
                    row_data['Why_It_Matters'] = ''
            except Exception:
                row_data['Plain_Explanation'] = ''
                row_data['Why_It_Matters'] = ''
            
            # Optimized Raw Rule extraction
            try:
                raw_obj = nr.raw_rule # Accessed directly via relationship
                raw_dict = None
                if raw_obj:
                    # Manually construct dict to avoid full to_dict overhead if needed, 
                    # but raw_rule.to_dict() is simple (just fields).
                    # However, to be safe and fast:
                    row_data['Raw_Rule_Text'] = raw_obj.rule_text or raw_obj.raw_text or ''
                    
                    # Create a lightweight dict for details
                    raw_dict = {
                        'id': raw_obj.id,
                        'rule_name': raw_obj.rule_name,
                        'source_file': raw_obj.source_file,
                        'line_number': raw_obj.file_line_number,
                        'action': raw_obj.action,
                        'protocol': raw_obj.protocol,
                        'source': raw_obj.source,
                        'destination': raw_obj.destination,
                        'service': raw_obj.destination, # logic might vary
                        'raw_text': raw_obj.raw_text
                    }
                else:
                    # Fallback
                    raw_dict = {
                        'id': safe('id'),
                        'rule_name': safe('rule_name'),
                        'raw_text': safe('raw_text')
                    }
                row_data['Raw_Rule_Details'] = json.dumps(raw_dict)
            except Exception:
                row_data['Raw_Rule_Details'] = ''
                row_data['Raw_Rule_Text'] = ''
            
            files_data[source_file].append(row_data)
        
        # Create Excel file with multiple sheets
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = []
            total_rules = 0
            total_compliant = 0
            total_non_compliant = 0
            severity_breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            top_violations = {}
            
            for source_file, rows in files_data.items():
                file_total = len(rows)
                file_compliant = len([r for r in rows if r['Compliance_Status'] == 'Compliant'])
                file_non_compliant = file_total - file_compliant
                
                summary_data.append({
                    'Source_File': source_file,
                    'Total_Rules': file_total,
                    'Compliant': file_compliant,
                    'Non_Compliant': file_non_compliant,
                    'Compliance_Percentage': round((file_compliant / file_total) * 100, 2) if file_total > 0 else 0
                })
                
                total_rules += file_total
                total_compliant += file_compliant
                total_non_compliant += file_non_compliant
                # Aggregate severity and violation types
                for r in rows:
                    sev = r.get('Severity')
                    if sev in severity_breakdown:
                        severity_breakdown[sev] += 1
                    vname = r.get('Compliance_Rule_Name')
                    if vname:
                        top_violations[vname] = top_violations.get(vname, 0) + (1 if r.get('Compliance_Status') == 'Non Compliant' else 0)
            
            # Add overall summary
            summary_data.append({
                'Source_File': 'OVERALL TOTAL',
                'Total_Rules': total_rules,
                'Compliant': total_compliant,
                'Non_Compliant': total_non_compliant,
                'Compliance_Percentage': round((total_compliant / total_rules) * 100, 2) if total_rules > 0 else 0
            })
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            # Dashboard sheet mimicking UI summary
            dash_rows = []
            dash_rows.append({'Metric': 'Total Rules', 'Value': total_rules})
            dash_rows.append({'Metric': 'Compliant Rules', 'Value': total_compliant})
            dash_rows.append({'Metric': 'Non-Compliant Rules', 'Value': total_non_compliant})
            dash_rows.append({'Metric': 'Compliance %', 'Value': round((total_compliant / total_rules) * 100, 2) if total_rules > 0 else 0})
            sev_rows = [{'Severity': k, 'Count': v} for k, v in severity_breakdown.items()]
            top_rows = sorted([{'Rule Name': k, 'Violations': v} for k, v in top_violations.items()], key=lambda x: x['Violations'], reverse=True)[:10]
            dash_df = pd.DataFrame(dash_rows)
            sev_df = pd.DataFrame(sev_rows)
            top_df = pd.DataFrame(top_rows)
            dash_df.to_excel(writer, sheet_name='Dashboard', index=False)
            # Use original writer to place sheets; add separate sheets for clarity
            sev_df.to_excel(writer, sheet_name='Severity Breakdown', index=False)
            top_df.to_excel(writer, sheet_name='Top Violations', index=False)
            
            # Individual file sheets
            for source_file, rows in files_data.items():
                # Clean sheet name (Excel sheet names have restrictions)
                sheet_name = source_file.replace('/', '_').replace('\\', '_')[:31]  # Max 31 chars
                df = pd.DataFrame(rows)
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        output.seek(0)
        return output.getvalue()
        
    except Exception as e:
        raise Exception(f"Error generating Excel export: {str(e)}")

def generate_excel_export_custom(review_session_id: str, options: Dict[str, Any]) -> bytes:
    try:
        include_compliant_opt = options.get('include_compliant')
        group_by = options.get('group_by')
        selected_fields = options.get('selected_fields') or []
        results = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.normalized_rule),
            joinedload(ReviewResult.compliance_rule),
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id).all()
        if include_compliant_opt is False:
            results = [r for r in results if r.status == 'non_compliant']
        def build_row(r: ReviewResult) -> Dict[str, Any]:
            nr = r.normalized_rule
            safe = lambda name: getattr(nr, name, '')
            base = {
                'Rule_ID': safe('id'),
                'Source_File': safe('source_file'),
                'Rule_Name': safe('rule_name'),
                'Action': safe('action'),
                'Protocol': safe('protocol'),
                'Source_IP': safe('source_ip'),
                'Source_Zone': safe('source_zone'),
                'Source_Port': safe('source_port'),
                'Dest_IP': safe('dest_ip'),
                'Dest_Zone': safe('dest_zone'),
                'Dest_Port': safe('dest_port'),
                'Service_Name': safe('service_name'),
                'Compliance_Status': r.status.replace('_', ' ').title(),
                'Severity': r.severity,
                'Compliance_Rule_Name': r.compliance_rule.rule_name if r.compliance_rule else ''
            }
            if selected_fields:
                filtered = {}
                for key in selected_fields:
                    if key in base:
                        filtered[key] = base[key]
                    else:
                        v = getattr(nr, key, None)
                        if v is not None:
                            filtered[key] = v
                return filtered
            return base
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in results:
            if group_by == 'severity':
                k = r.severity or 'Unknown'
            elif group_by == 'rule':
                k = (r.compliance_rule.rule_name if r.compliance_rule else 'Unknown')
            else:
                k = r.normalized_rule.source_file
            groups.setdefault(k, []).append(build_row(r))
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            for name, rows in groups.items():
                df = pd.DataFrame(rows)
                sheet_name = str(name).replace('/', '_').replace('\\', '_')[:31]
                if df.empty:
                    df = pd.DataFrame(columns=selected_fields or list(build_row(results[0]).keys()) if results else [])
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        output.seek(0)
        return output.getvalue()
    except Exception as e:
        raise Exception(f"Error generating custom Excel export: {str(e)}")

def generate_csv_export(review_session_id: str, source_file: Optional[str] = None, include_compliant: Optional[bool] = None) -> bytes:
    """
    Generate CSV export with compliance status columns.
    If source_file is specified, export only that file's data.
    Otherwise, export all data in a single CSV.
    """
    try:
        # Get review results
        # Optimize: Eager load raw_rule
        query = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.normalized_rule).joinedload(NormalizedRule.raw_rule),
            joinedload(ReviewResult.compliance_rule),
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id)
        
        if source_file:
            query = query.join(NormalizedRule).filter(NormalizedRule.source_file == source_file)
        
        results = query.all()
        if include_compliant is not None and include_compliant is False:
            results = [r for r in results if r.status == 'non_compliant']
        
        if not results:
            columns = [
                'Rule_ID','Source_File','Action','Protocol','Source_IP','Source_Zone','Source_Port','Dest_IP','Dest_Zone','Dest_Port',
                'Service_Name','Source_VLAN','Dest_VLAN','Interface','Direction','Logging','Description',
                'Original_Rule','Raw_Text','Raw_Rule_Text','Compliance_Status','Failed_Checks','Severity','Compliance_Rule_Name',
                'Check_Description','Notes','Checked_At','Raw_Rule_Details','Source_PCI_DSS_Categories','Dest_PCI_DSS_Categories'
            ]
            df = pd.DataFrame(columns=columns)
            output = io.StringIO()
            df.to_csv(output, index=False)
            return output.getvalue().encode('utf-8')
        
        # Optimization: Pre-fetch CMDB PCI data for O(1) lookup
        assets = db.session.query(CMDBAsset.ip_address, CMDBAsset.hostname, CMDBAsset.additional_data).all()
        ip_pci_map = {}
        host_pci_map = {}
        
        for ip, hostname, data in assets:
            if not data:
                continue
            try:
                d = json.loads(data)
                cat = d.get('pcidss_asset_category')
                if cat:
                    if ip:
                        ip_pci_map[ip] = cat
                    if hostname:
                        host_pci_map[hostname.lower()] = cat
            except:
                pass

        def get_pci_categories(ip_field: str, hostname_field: str = None) -> str:
            cats = set()
            if ip_field:
                tokens = [t.strip() for t in ip_field.replace(';', ',').split(',')]
                for t in tokens:
                    t_clean = t.lower().replace('host ', '').strip()
                    if t_clean in ip_pci_map:
                        cats.add(ip_pci_map[t_clean])
            if hostname_field:
                h_clean = hostname_field.lower().strip()
                if h_clean in host_pci_map:
                    cats.add(host_pci_map[h_clean])
            return ', '.join(sorted(list(cats)))

        # Create CSV data
        csv_data = []
        for result in results:
            nr = result.normalized_rule
            safe = lambda name: getattr(nr, name, '')
            
            # Use optimized lookup
            src_cats = get_pci_categories(nr.source_ip, nr.source_hostname)
            dst_cats = get_pci_categories(nr.dest_ip, nr.dest_hostname)
            
            row_data = {
                'Rule_ID': safe('id'),
                'Source_File': safe('source_file'),
                'Action': safe('action'),
                'Protocol': safe('protocol'),
                'Source_IP': safe('source_ip'),
                'Source_Zone': safe('source_zone'),
                'Source_Port': safe('source_port'),
                'Dest_IP': safe('dest_ip'),
                'Dest_Zone': safe('dest_zone'),
                'Dest_Port': safe('dest_port'),
                'Service_Name': safe('service_name'),
                'Source_VLAN': safe('source_vlan'),
                'Dest_VLAN': safe('dest_vlan'),
                'Interface': safe('interface'),
                'Direction': safe('direction'),
                'Logging': safe('logging'),
                'Description': safe('description'),
                'Original_Rule': safe('original_rule'),
                'Raw_Text': safe('raw_text'),
                'Raw_Rule_Text': '',
                'Source_PCI_DSS_Categories': src_cats,
                'Dest_PCI_DSS_Categories': dst_cats,
                # New compliance columns
                'Compliance_Status': result.status.replace('_', ' ').title(),
                'Failed_Checks': len(result.failed_checks) if result.failed_checks else 0,
                'Severity': result.severity,
                'Compliance_Rule_Name': result.compliance_rule.rule_name if result.compliance_rule else '',
                'Check_Description': result.compliance_rule.description if result.compliance_rule else '',
                'Notes': result.notes or '',
                'Checked_At': result.checked_at.strftime('%Y-%m-%d %H:%M:%S') if result.checked_at else ''
            }
            try:
                raw_obj = nr.raw_rule
                raw_dict = None
                if raw_obj:
                    row_data['Raw_Rule_Text'] = raw_obj.rule_text or raw_obj.raw_text or ''
                    raw_dict = {
                        'id': raw_obj.id,
                        'rule_name': raw_obj.rule_name,
                        'source_file': raw_obj.source_file,
                        'line_number': raw_obj.file_line_number,
                        'action': raw_obj.action,
                        'protocol': raw_obj.protocol,
                        'source': raw_obj.source,
                        'destination': raw_obj.destination,
                        'service': raw_obj.destination,
                        'raw_text': raw_obj.raw_text
                    }
                else:
                    raw_dict = {
                        'id': safe('id'),
                        'rule_name': safe('rule_name'),
                        'raw_text': safe('raw_text')
                    }
                row_data['Raw_Rule_Details'] = json.dumps(raw_dict)
            except Exception:
                row_data['Raw_Rule_Details'] = ''
                row_data['Raw_Rule_Text'] = ''
            
            csv_data.append(row_data)
        
        # Convert to CSV
        df = pd.DataFrame(csv_data)
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue().encode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error generating CSV export: {str(e)}")

def generate_csv_export_custom(review_session_id: str, options: Dict[str, Any]) -> bytes:
    try:
        source_file = options.get('source_file')
        include_compliant_opt = options.get('include_compliant')
        selected_fields = options.get('selected_fields') or []
        query = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.normalized_rule),
            joinedload(ReviewResult.compliance_rule),
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id)
        if source_file:
            query = query.join(NormalizedRule).filter(NormalizedRule.source_file == source_file)
        results = query.all()
        if include_compliant_opt is False:
            results = [r for r in results if r.status == 'non_compliant']
        rows = []
        for r in results:
            nr = r.normalized_rule
            # Aggregate PCI DSS categories
            try:
                nr_full = nr.to_dict()
                src_cats = list({m.get('pcidss_asset_category') for m in (nr_full.get('source_cmdb_matches') or []) if m.get('pcidss_asset_category')})
                dst_cats = list({m.get('pcidss_asset_category') for m in (nr_full.get('dest_cmdb_matches') or []) if m.get('pcidss_asset_category')})
            except Exception:
                src_cats = []
                dst_cats = []
            base = {
                'Rule_ID': getattr(nr, 'id', ''),
                'Source_File': getattr(nr, 'source_file', ''),
                'Rule_Name': getattr(nr, 'rule_name', ''),
                'Action': getattr(nr, 'action', ''),
                'Protocol': getattr(nr, 'protocol', ''),
                'Source_IP': getattr(nr, 'source_ip', ''),
                'Source_Zone': getattr(nr, 'source_zone', ''),
                'Source_Port': getattr(nr, 'source_port', ''),
                'Dest_IP': getattr(nr, 'dest_ip', ''),
                'Dest_Zone': getattr(nr, 'dest_zone', ''),
                'Dest_Port': getattr(nr, 'dest_port', ''),
                'Service_Name': getattr(nr, 'service_name', ''),
                'Source_PCI_DSS_Categories': ', '.join(src_cats),
                'Dest_PCI_DSS_Categories': ', '.join(dst_cats),
                'Compliance_Status': r.status.replace('_', ' ').title(),
                'Severity': r.severity,
                'Compliance_Rule_Name': r.compliance_rule.rule_name if r.compliance_rule else ''
            }
            if selected_fields:
                filtered = {}
                for key in selected_fields:
                    if key in base:
                        filtered[key] = base[key]
                    else:
                        v = getattr(nr, key, None)
                        if v is not None:
                            filtered[key] = v
                rows.append(filtered)
            else:
                rows.append(base)
        df = pd.DataFrame(rows)
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue().encode('utf-8')
    except Exception as e:
        raise Exception(f"Error generating custom CSV export: {str(e)}")

def get_available_source_files(review_session_id: str) -> List[str]:
    """
    Get list of source files available for export in a review session.
    """
    try:
        files = db.session.query(NormalizedRule.source_file).distinct().join(
            ReviewResult, ReviewResult.normalized_rule_id == NormalizedRule.id
        ).filter(ReviewResult.review_session_id == review_session_id).all()
        
        return [file[0] for file in files]
        
    except Exception as e:
        raise Exception(f"Error getting source files: {str(e)}")

def get_export_metadata(review_session_id: str) -> Dict[str, Any]:
    """
    Get metadata about the export (file counts, review info, etc.)
    """
    try:
        # Get review session info
        first_result = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id).first()
        
        if not first_result:
            raise ValueError("Review session not found")
        
        # Get statistics
        total_results = db.session.query(ReviewResult).filter(
            ReviewResult.review_session_id == review_session_id
        ).count()
        
        compliant_count = db.session.query(ReviewResult).filter(
            ReviewResult.review_session_id == review_session_id,
            ReviewResult.status == 'compliant'
        ).count()
        
        source_files = get_available_source_files(review_session_id)
        
        return {
            'review_session_id': review_session_id,
            'profile_name': first_result.profile.profile_name,
            'compliance_framework': first_result.profile.compliance_framework,
            'total_rules': total_results,
            'compliant_rules': compliant_count,
            'non_compliant_rules': total_results - compliant_count,
            'compliance_percentage': round((compliant_count / total_results) * 100, 2) if total_results > 0 else 0,
            'source_files': source_files,
            'export_generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    except Exception as e:
        raise Exception(f"Error getting export metadata: {str(e)}")