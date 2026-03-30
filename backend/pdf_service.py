from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
import json
import io
from typing import List, Dict, Any, Optional
from models import db, ReviewResult, NormalizedRule, ComplianceRule, ReviewProfile
from sqlalchemy.orm import joinedload
from export_service import get_export_metadata

def generate_pdf_report(review_session_id: str, options: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Generate a comprehensive PDF report for a review session.
    Returns the PDF file as bytes.
    """
    try:
        # Create PDF buffer
        buffer = io.BytesIO()
        
        # Create document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        small_style = ParagraphStyle(
            'SmallText',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.black
        )
        
        # Get metadata and results
        metadata = get_export_metadata(review_session_id)
        include_compliant_opt = (options or {}).get('include_compliant')
        if include_compliant_opt is None:
            include_compliant = True
        elif isinstance(include_compliant_opt, bool):
            include_compliant = include_compliant_opt
        else:
            s = str(include_compliant_opt).strip().lower()
            include_compliant = s in ('1','true','yes','y','on')
        source_file_filter = (options or {}).get('source_file')
        group_by = (options or {}).get('group_by')  # 'severity' | 'rule' | 'source_file' | None
        if not group_by:
            group_by = 'rule'
        include_sections = (options or {}).get('include_sections') or []
        # Query with optional source_file filter
        base_query = db.session.query(ReviewResult).options(
            joinedload(ReviewResult.normalized_rule),
            joinedload(ReviewResult.compliance_rule),
            joinedload(ReviewResult.profile)
        ).filter(ReviewResult.review_session_id == review_session_id)
        if source_file_filter:
            base_query = base_query.join(NormalizedRule).filter(NormalizedRule.source_file == source_file_filter)
        results = base_query.all()
        
        # Build story (content)
        story = []
        
        # Title page
        story.append(Paragraph("Firewall Compliance Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        if (not include_sections) or ('summary' in include_sections):
            story.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ['Profile Name:', metadata['profile_name']],
            ['Compliance Framework:', metadata['compliance_framework']],
            ['Review Session ID:', review_session_id],
            ['Generated On:', metadata['export_generated_at']],
            ['Total Rules Analyzed:', str(metadata['total_rules'])],
            ['Compliant Rules:', str(metadata['compliant_rules'])],
            ['Non-Compliant Rules:', str(metadata['non_compliant_rules'])],
            ['Overall Compliance:', f"{metadata['compliance_percentage']}%"]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Compliance Status Overview
        story.append(Paragraph("Compliance Status Overview", heading_style))
        
        # Group results by status and severity
        status_counts = {'compliant': 0, 'non_compliant': 0}
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for result in results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
            if result.severity:
                severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
        
        # Status breakdown table
        status_data = [
            ['Status', 'Count', 'Percentage'],
            ['Compliant', str(status_counts.get('compliant', 0)), 
             f"{(status_counts.get('compliant', 0) / len(results) * 100):.1f}%" if results else "0%"],
            ['Non-Compliant', str(status_counts.get('non_compliant', 0)), 
             f"{(status_counts.get('non_compliant', 0) / len(results) * 100):.1f}%" if results else "0%"]
        ]
        
        status_table = Table(status_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        status_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        if (not include_sections) or ('summary' in include_sections):
            story.append(status_table)
            story.append(Spacer(1, 20))
        compliant_count = status_counts.get('compliant', 0)
        non_compliant_count = status_counts.get('non_compliant', 0)
        pie_drawing = Drawing(300, 200)
        pie = Pie()
        pie.x = 75
        pie.y = 20
        pie.width = 150
        pie.height = 150
        pie.data = [compliant_count, non_compliant_count]
        pie.labels = ['Compliant', 'Non-Compliant']
        pie.slices[0].fillColor = colors.green
        pie.slices[1].fillColor = colors.red
        pie_drawing.add(pie)
        if (not include_sections) or ('charts' in include_sections) or ('severity_chart' in include_sections):
            story.append(Paragraph("Compliance Distribution", heading_style))
            story.append(pie_drawing)
            story.append(Spacer(1, 20))

        # Review Page Snapshot
        snapshot_pool = results if include_compliant else [r for r in results if r.status == 'non_compliant']
        if snapshot_pool and ((not include_sections) or ('details' in include_sections)):
            story.append(Paragraph("Review Page Snapshot", heading_style))
            snap_header = ["Source File", "Rule Details", "Compliance Rule", "Compliance", "Severity"]
            snap_rows = [snap_header]
            for r in snapshot_pool:
                nr = r.normalized_rule
                details_line1 = f"{nr.action or 'N/A'} {nr.protocol or ''}".strip()
                src = nr.source_ip or 'N/A'
                dst = nr.dest_ip or 'N/A'
                details_line2 = f"{src} → {dst}"
                service = nr.service_name or ''
                details = f"{details_line1}\n{details_line2} {('(' + service + ')') if service else ''}"
                snap_rows.append([
                    nr.source_file or 'N/A',
                    details,
                    r.compliance_rule.rule_name if r.compliance_rule else 'N/A',
                    r.status.replace('_',' ').title(),
                    r.severity or 'N/A'
                ])
            snap_table = Table(snap_rows, colWidths=[1.6*inch, 2.4*inch, 1.2*inch, 1.0*inch, 0.9*inch])
            snap_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
            ]))
            story.append(snap_table)
            story.append(Spacer(1, 12))

        # Severity breakdown
        if any(severity_counts.values()) and (((not include_sections) or ('charts' in include_sections) or ('severity_chart' in include_sections))):
            story.append(Paragraph("Severity Breakdown (Non-Compliant Rules)", heading_style))
            
            severity_data = [['Severity', 'Count']]
            for severity, count in severity_counts.items():
                if count > 0:
                    severity_data.append([severity, str(count)])
            
            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(severity_table)
            bar_drawing = Drawing(400, 200)
            bar = VerticalBarChart()
            bar.x = 50
            bar.y = 30
            bar.height = 140
            bar.width = 300
            bar.data = [[severity_counts.get('Critical', 0), severity_counts.get('High', 0), severity_counts.get('Medium', 0), severity_counts.get('Low', 0)]]
            bar.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
            bar.bars[0].fillColor = colors.darkred
            bar.barLabels.nudge = 7
            bar.barLabels.fontName = 'Helvetica'
            bar.barLabels.fontSize = 8
            bar_drawing.add(bar)
            story.append(bar_drawing)
            story.append(Spacer(1, 20))

        # Top violations by compliance rule
        top_rule_counts: Dict[str, int] = {}
        for r in results:
            if r.status == 'non_compliant' and r.compliance_rule:
                name = r.compliance_rule.rule_name
                top_rule_counts[name] = top_rule_counts.get(name, 0) + 1
        if top_rule_counts and (((not include_sections) or ('charts' in include_sections) or ('violations_chart' in include_sections))):
            story.append(Paragraph("Top Violations (Compliance Rules)", heading_style))
            top_sorted = sorted(top_rule_counts.items(), key=lambda x: (-x[1], x[0]))[:10]
            top_table_data = [["Compliance Rule", "Findings"]] + [[k, str(v)] for k, v in top_sorted]
            top_table = Table(top_table_data, colWidths=[4*inch, 1.5*inch])
            top_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(top_table)
            story.append(Spacer(1, 12))
            bar2 = VerticalBarChart()
            bar2.x = 50
            bar2.y = 30
            bar2.height = 140
            bar2.width = 300
            bar2.data = [[v for _, v in top_sorted]]
            bar2.categoryAxis.categoryNames = [k for k, _ in top_sorted]
            bar2.barLabels.nudge = 7
            bar2.barLabels.fontName = 'Helvetica'
            bar2.barLabels.fontSize = 8
            bar2.bars[0].fillColor = colors.darkblue
            drawing2 = Drawing(400, 200)
            drawing2.add(bar2)
            story.append(drawing2)
            story.append(Spacer(1, 20))

        # File compliance overview
        file_counts: Dict[str, Dict[str, int]] = {}
        for r in results:
            f = r.normalized_rule.source_file
            d = file_counts.setdefault(f, {'total': 0, 'compliant': 0, 'non_compliant': 0})
            d['total'] += 1
            if r.status == 'compliant':
                d['compliant'] += 1
            else:
                d['non_compliant'] += 1
        if file_counts and (((not include_sections) or ('summary' in include_sections))):
            story.append(Paragraph("File Compliance Overview", heading_style))
            file_rows = [["Source File", "Total", "Compliant", "Non-Compliant", "Compliance %"]]
            for f, d in file_counts.items():
                pct = round((d['compliant'] / d['total']) * 100, 2) if d['total'] > 0 else 0
                file_rows.append([f, str(d['total']), str(d['compliant']), str(d['non_compliant']), f"{pct}%"])
            file_table = Table(file_rows, colWidths=[3.5*inch, 0.8*inch, 0.9*inch, 1.1*inch, 1.0*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(file_table)
            story.append(Spacer(1, 12))
            names = list(file_counts.keys())
            percents = [round((d['compliant'] / d['total']) * 100, 2) if d['total'] > 0 else 0 for d in file_counts.values()]
            bar3 = VerticalBarChart()
            bar3.x = 50
            bar3.y = 30
            bar3.height = 140
            bar3.width = 300
            bar3.data = [percents]
            bar3.categoryAxis.categoryNames = names
            bar3.barLabels.nudge = 7
            bar3.barLabels.fontName = 'Helvetica'
            bar3.barLabels.fontSize = 8
            bar3.bars[0].fillColor = colors.green
            drawing3 = Drawing(400, 200)
            drawing3.add(bar3)
            story.append(drawing3)
            story.append(Spacer(1, 20))

        # Contents (Non-Compliant Findings by Compliance Rule)
        rule_counts = {}
        for r in results:
            if r.status == 'non_compliant' and r.compliance_rule:
                rn = r.compliance_rule.rule_name
                rule_counts[rn] = rule_counts.get(rn, 0) + 1
        if rule_counts and ((not include_sections) or ('details' in include_sections)):
            story.append(Paragraph("Contents (Non-Compliant Findings by Compliance Rule)", heading_style))
            contents_data = [["Compliance Rule", "Findings"]] + [[k, str(v)] for k, v in sorted(rule_counts.items(), key=lambda x: (-x[1], x[0]))]
            contents_table = Table(contents_data, colWidths=[4*inch, 1.5*inch])
            contents_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(contents_table)
            story.append(Spacer(1, 20))
        
        # Page break before detailed sections
        if (not include_sections) or ('details' in include_sections):
            story.append(PageBreak())
        
        # Detailed Findings
        detailed_pool = results if include_compliant else [r for r in results if r.status == 'non_compliant']
        section_title = "Detailed Findings - All Rules" if include_compliant else "Detailed Findings - Non-Compliant Rules"
        if detailed_pool and (((not include_sections) or ('details' in include_sections))):
            story.append(Paragraph(section_title, heading_style))
            # Optional grouping
            groups: Dict[str, List[ReviewResult]] = {}
            if group_by == 'severity':
                for r in detailed_pool:
                    key = r.severity or 'N/A'
                    groups.setdefault(key, []).append(r)
            elif group_by == 'rule':
                for r in detailed_pool:
                    key = r.compliance_rule.rule_name if r.compliance_rule else 'N/A'
                    groups.setdefault(key, []).append(r)
            elif group_by == 'source_file':
                for r in detailed_pool:
                    key = r.normalized_rule.source_file
                    groups.setdefault(key, []).append(r)
            else:
                groups['All'] = detailed_pool
            seq = 1
            for group_name, group_results in groups.items():
                if group_by:
                    story.append(Paragraph(f"Group: {group_by.replace('_',' ').title()} = {group_name}", styles['Heading3']))
                # Rule purpose and control intent (for group_by=rule)
                try:
                    if group_by == 'rule' and group_results and group_results[0].compliance_rule:
                        cr = group_results[0].compliance_rule
                        ctrl_rows = [
                            ['Rule Name', cr.rule_name],
                            ['Severity', cr.severity or 'N/A'],
                            ['Control Intent', cr.description or 'No description'],
                            ['Field', getattr(cr, 'field_to_check', 'N/A')],
                            ['Operator', getattr(cr, 'operator', 'N/A')],
                            ['Expected Value', getattr(cr, 'value', 'N/A')]
                        ]
                        ctrl_table = Table(ctrl_rows, colWidths=[1.7*inch, 3.8*inch])
                        ctrl_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('BACKGROUND', (1, 0), (1, -1), colors.white),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP')
                        ]))
                        story.append(ctrl_table)
                        story.append(Spacer(1, 12))
                except Exception:
                    pass
                for result in group_results:
                    # Rule header
                    rule_header = f"Finding #{seq}: {result.compliance_rule.rule_name if result.compliance_rule else 'Unknown Rule'}"
                    story.append(Paragraph(rule_header, styles['Heading3']))
                    
                    # Rule details table
                    rule_data = [
                        ['Source File:', result.normalized_rule.source_file],
                        ['Rule ID:', str(result.normalized_rule.id)],
                        ['Action:', result.normalized_rule.action or 'N/A'],
                        ['Protocol:', result.normalized_rule.protocol or 'N/A'],
                        ['Source IP:', result.normalized_rule.source_ip or 'N/A'],
                        ['Destination IP:', result.normalized_rule.dest_ip or 'N/A'],
                        ['Service:', result.normalized_rule.service_name or 'N/A'],
                        ['Severity:', result.severity or 'N/A'],
                        ['Compliance Rule:', result.compliance_rule.rule_name if result.compliance_rule else 'N/A'],
                        ['Description:', result.compliance_rule.description if result.compliance_rule else 'N/A']
                    ]
                
                rule_table = Table(rule_data, colWidths=[1.5*inch, 4*inch])
                rule_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('BACKGROUND', (1, 0), (1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                
                story.append(rule_table)
                # Add rule snapshot (raw_text and rule_text if available)
                raw_text = getattr(result.normalized_rule, 'raw_text', None)
                rule_text = getattr(result.normalized_rule, 'rule_text', None)
                if raw_text or rule_text:
                    story.append(Spacer(1, 6))
                    story.append(Paragraph("Rule Snapshot:", styles['Heading4']))
                    if rule_text:
                        story.append(Paragraph(str(rule_text), styles['Normal']))
                    if raw_text:
                        story.append(Paragraph(str(raw_text), styles['Normal']))
                
                if result.failed_checks:
                    story.append(Spacer(1, 10))
                    story.append(Paragraph("Failed Compliance Checks:", styles['Heading4']))
                    # Failed checks may be stored as JSON string; parse safely
                    try:
                        checks = json.loads(result.failed_checks) if isinstance(result.failed_checks, str) else (result.failed_checks or [])
                    except Exception:
                        checks = []
                    for j, check in enumerate(checks, 1):
                        desc = check.get('description', 'No description') if isinstance(check, dict) else str(check)
                        field = check.get('field_checked', 'N/A') if isinstance(check, dict) else 'N/A'
                        expected = check.get('expected_value', 'N/A') if isinstance(check, dict) else 'N/A'
                        actual = check.get('actual_value', 'N/A') if isinstance(check, dict) else 'N/A'
                        op = check.get('operator', '') if isinstance(check, dict) else ''
                        # Summary line for the failed check
                        summary_text = f"{j}. {desc}<br/>   Field: {field}<br/>   Expected: {expected}<br/>   Actual: {actual}"
                        story.append(Paragraph(summary_text, styles['Normal']))
                        # Build explanation table (Context, Observation, Risk, Recommendation)
                        meaning = _operator_plain_meaning(op, expected, actual)
                        risk_text = _risk_text(result.severity, field, expected, actual, result.normalized_rule.action, result.normalized_rule.dest_port)
                        rec = _recommendation(field, op, expected, actual)
                        context_text = (result.compliance_rule.description or 'No description') + "<br/>Meaning: " + meaning
                        observation_text = f"Field '{field}' is '{actual}', expected '{expected}'."
                        explanation_rows = [
                            ['Context of Check', context_text],
                            ['Observation', observation_text],
                            ['Risk', risk_text],
                            ['Recommendation', rec]
                        ]
                        explain_table = Table(explanation_rows, colWidths=[2*inch, 4*inch])
                        explain_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('BACKGROUND', (1, 0), (1, -1), colors.white),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP')
                        ]))
                        story.append(explain_table)
                        details_rows = [
                            ['Rule ID', str(getattr(result.normalized_rule, 'id', ''))],
                            ['Rule Name', getattr(result.normalized_rule, 'rule_name', '') or 'N/A'],
                            ['Action', getattr(result.normalized_rule, 'action', '') or 'N/A'],
                            ['Protocol', getattr(result.normalized_rule, 'protocol', '') or 'N/A'],
                            ['Source IP', getattr(result.normalized_rule, 'source_ip', '') or 'N/A'],
                            ['Source Port', getattr(result.normalized_rule, 'source_port', '') or 'N/A'],
                            ['Destination IP', getattr(result.normalized_rule, 'dest_ip', '') or 'N/A'],
                            ['Destination Port', getattr(result.normalized_rule, 'dest_port', '') or 'N/A'],
                            ['Service Name', getattr(result.normalized_rule, 'service_name', '') or 'N/A'],
                            ['Source VLAN', getattr(result.normalized_rule, 'source_vlan', '') or 'N/A'],
                            ['Destination VLAN', getattr(result.normalized_rule, 'dest_vlan', '') or 'N/A'],
                            ['Interface', getattr(result.normalized_rule, 'interface', '') or 'N/A'],
                            ['Direction', getattr(result.normalized_rule, 'direction', '') or 'N/A'],
                            ['Logging', getattr(result.normalized_rule, 'logging', '') or 'N/A'],
                            ['Description', getattr(result.normalized_rule, 'description', '') or 'N/A'],
                            ['Original Rule', getattr(result.normalized_rule, 'original_rule', '') or 'N/A']
                        ]
                        details_table = Table(details_rows, colWidths=[1.7*inch, 3.8*inch])
                        details_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('BACKGROUND', (1, 0), (1, -1), colors.white),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP')
                        ]))
                        story.append(details_table)
                        story.append(Spacer(1, 10))
                else:
                    # Even if failed_checks are not persisted, provide a narrative based on the rule definition
                    story.append(Spacer(1, 8))
                    story.append(Paragraph("Narrative Summary:", styles['Heading4']))
                    try:
                        field = result.compliance_rule.field_to_check or 'N/A'
                        op = result.compliance_rule.operator or ''
                        expected = result.compliance_rule.value or ''
                        # Resolve actual field value from normalized rule
                        actual_base = getattr(result.normalized_rule, field, None)
                        if actual_base is None and field in ('rule_text','raw_text'):
                            raw = getattr(result.normalized_rule, 'raw_rule', None)
                            if raw is not None:
                                actual_base = getattr(raw, field, None)
                        actual = str(actual_base or 'N/A')
                        meaning = _operator_plain_meaning(op, expected, actual)
                        risk_text = _risk_text(result.severity, field, expected, actual, result.normalized_rule.action, result.normalized_rule.dest_port)
                        rec = _recommendation(field, op, expected, actual)
                        context_text = (result.compliance_rule.description or 'No description') + "<br/>Meaning: " + meaning
                        observation_text = f"Field '{field}' is '{actual}', expected '{expected}'."
                        explanation_rows = [
                            ['Context of Check', context_text],
                            ['Observation', observation_text],
                            ['Risk', risk_text],
                            ['Recommendation', rec]
                        ]
                        explain_table = Table(explanation_rows, colWidths=[2*inch, 4*inch])
                        explain_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('BACKGROUND', (1, 0), (1, -1), colors.white),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP')
                        ]))
                        story.append(explain_table)
                        story.append(Spacer(1, 10))
                    except Exception:
                        # If anything fails, continue with next entries
                        pass
                    
                story.append(Spacer(1, 15))
                seq += 1
                # Add page break every 3 findings to avoid overcrowding
                if seq % 3 == 1 and seq-1 < len(group_results):
                    story.append(PageBreak())
        # Appendices (always included)
        if (not include_sections) or ('appendices' in include_sections):
            story.append(PageBreak())
            story.append(Paragraph("Appendix A - All Rules Summary", heading_style))
        summary_header = ['Rule ID','Source File','Action','Protocol','Source IP','Destination IP','Service','Status','Severity','Compliance Rule']
        summary_rows = [summary_header]
        for r in results:
            summary_rows.append([
                str(getattr(r.normalized_rule,'id','')),
                getattr(r.normalized_rule,'source_file','') or 'N/A',
                getattr(r.normalized_rule,'action','') or 'N/A',
                getattr(r.normalized_rule,'protocol','') or 'N/A',
                getattr(r.normalized_rule,'source_ip','') or 'N/A',
                getattr(r.normalized_rule,'dest_ip','') or 'N/A',
                getattr(r.normalized_rule,'service_name','') or 'N/A',
                r.status.replace('_',' ').title(),
                r.severity or 'N/A',
                r.compliance_rule.rule_name if r.compliance_rule else 'N/A'
            ])
        summary_table = Table(summary_rows, colWidths=[0.7*inch,1.2*inch,0.8*inch,0.8*inch,1.4*inch,1.4*inch,1.0*inch,0.8*inch,0.8*inch,1.2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
        ]))
        if (not include_sections) or ('appendices' in include_sections):
            story.append(summary_table)
            story.append(Spacer(1, 20))
            story.append(Paragraph("Appendix B - Raw Rule Details", heading_style))
        for r in (results if ((not include_sections) or ('appendices' in include_sections)) else []):
            story.append(Paragraph(f"Rule {getattr(r.normalized_rule,'id','')}: {getattr(r.normalized_rule,'rule_name','') or 'N/A'}", styles['Heading3']))
            raw_obj = getattr(r, 'raw_rule', None) or getattr(r.normalized_rule, 'raw_rule', None)
            raw_dict = None
            try:
                if raw_obj and hasattr(raw_obj,'to_dict'):
                    raw_dict = raw_obj.to_dict()
            except Exception:
                raw_dict = None
            if raw_dict:
                raw_rows = [["Field","Value"]]
                for k,v in raw_dict.items():
                    raw_rows.append([str(k), str(v if v is not None else '')])
                raw_table = Table(raw_rows, colWidths=[1.5*inch, 4.5*inch])
                raw_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                story.append(raw_table)
            else:
                story.append(Paragraph("No raw rule payload available.", styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Append Glossary
        if (not include_sections) or ('appendices' in include_sections):
            story.append(PageBreak())
            for flow in _glossary_section():
                story.append(flow)
        # Build PDF
        doc.build(story)
        
        # Get PDF data
        buffer.seek(0)
        return buffer.getvalue()
        
    except Exception as e:
        raise Exception(f"Error generating PDF report: {str(e)}")

def _glossary_section() -> List[Any]:
    styles = getSampleStyleSheet()
    items = []
    items.append(Paragraph("Glossary of Terms", styles['Heading2']))
    entries = [
        ("Protocol", "Rules for how data is sent (e.g., TCP, UDP)."),
        ("Port", "A number used to identify services (e.g., 443 for HTTPS)."),
        ("Allow/Permit", "Means traffic is allowed through the firewall."),
        ("Deny/Block", "Means traffic is stopped by the firewall."),
        ("Severity", "How important a problem is: Critical, High, Medium, Low."),
        ("Compliance Rule", "A rule that checks if firewall settings match policy."),
        ("Service", "Named application or protocol like SSH, DNS, HTTPS."),
    ]
    for term, definition in entries:
        items.append(Paragraph(f"<b>{term}:</b> {definition}", styles['Normal']))
    return items

def get_pdf_metadata(review_session_id: str) -> Dict[str, Any]:
    """
    Get metadata for PDF report generation.
    """
    try:
        metadata = get_export_metadata(review_session_id)
        
        # Add PDF-specific metadata
        metadata.update({
            'pdf_title': f"Compliance Report - {metadata['profile_name']}",
            'pdf_subject': f"Firewall Compliance Analysis for {metadata['compliance_framework']}",
            'pdf_author': "Firewall Review System",
            'pdf_creator': "FRR PDF Service"
        })
        
        return metadata
        
    except Exception as e:
        raise Exception(f"Error getting PDF metadata: {str(e)}")
def _operator_plain_meaning(op: str, expected: str, actual: str) -> str:
    op = (op or '').lower()
    if op == 'equals':
        return f"It should equal '{expected}', but is '{actual}'."
    if op == 'not_equals':
        return f"It should not equal '{expected}', but is '{actual}'."
    if op == 'contains':
        return f"It should include any of '{expected}', but currently is '{actual}'."
    if op == 'not_contains':
        return f"It should not include any of '{expected}', but currently is '{actual}'."
    if op == 'in_list':
        return f"It should be one of '{expected}', but is '{actual}'."
    if op == 'not_in_list':
        return f"It should not be any of '{expected}', but is '{actual}'."
    if op == 'regex_match':
        return f"It should match pattern '{expected}', but value is '{actual}'."
    if op == 'not_regex_match':
        return f"It should not match pattern '{expected}', but value is '{actual}'."
    if op == 'starts_with':
        return f"It should start with '{expected}', but value is '{actual}'."
    if op == 'ends_with':
        return f"It should end with '{expected}', but value is '{actual}'."
    if op == 'is_empty':
        return f"It should be empty, but value is '{actual}'."
    if op == 'is_not_empty':
        return f"It should not be empty, but value is empty."
    if op == 'greater_than':
        return f"It should be greater than '{expected}', but is '{actual}'."
    if op == 'greater_than_or_equal':
        return f"It should be at least '{expected}', but is '{actual}'."
    if op == 'less_than':
        return f"It should be less than '{expected}', but is '{actual}'."
    if op == 'less_than_or_equal':
        return f"It should be at most '{expected}', but is '{actual}'."
    if op == 'composite':
        return "This check combines several rules (AND/OR/NOT). See failed checks below."
    return f"Expected '{expected}' with operator '{op}', actual '{actual}'."

def _risk_text(severity: Optional[str], field: str, expected: str, actual: str, action: Optional[str], dest_port: Optional[str]) -> str:
    sev = (severity or '').lower()
    act = (action or '').lower()
    if act in ('deny','block','drop'):
        return 'Traffic is denied; risk is mitigated by policy.'
    base = f"Field '{field}' is '{actual}', expected '{expected}'."
    if sev in ('critical','high'):
        return base + " Potential exposure to sensitive services or networks."
    if sev in ('medium','low'):
        return base + " May impact segmentation or logging requirements."
    return base

def _recommendation(field: str, op: str, expected: str, actual: str) -> str:
    op = (op or '').lower()
    if op in ('equals','not_equals','contains','not_contains','in_list','not_in_list'):
        return f"Update '{field}' to meet policy: expected '{expected}'."
    if op in ('greater_than','greater_than_or_equal','less_than','less_than_or_equal'):
        return f"Adjust '{field}' threshold to '{expected}'."
    if op in ('regex_match','not_regex_match'):
        return f"Align '{field}' to pattern '{expected}'."
    if op in ('is_empty','is_not_empty'):
        return f"Set '{field}' per policy to satisfy emptiness requirement."
    if op == 'composite':
        return "Review combined conditions and fix each violating sub-check."
    return f"Bring '{field}' in line with expected '{expected}'."