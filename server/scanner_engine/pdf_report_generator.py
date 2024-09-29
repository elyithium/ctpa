from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

def generate_reportlab_pdf(site, summary, category_summary, detailed_results, file_path='./reports/vulnerability_report.pdf'):
    try:
        # Create the PDF document
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        elements = []

        # Styles
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading1']
        subheading_style = styles['Heading2']
        sub2heading_style = styles['Heading3']
        normal_style = styles['BodyText']

        # Title
        elements.append(Paragraph("DAST Scanning Report", title_style))
        elements.append(Spacer(1, 12))

        # Site and Date Info (as Heading3)
        elements.append(Paragraph(f"Site: {site}", subheading_style))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S')}", sub2heading_style))
        elements.append(Spacer(1, 12))

        # Summary of Alerts
        elements.append(Paragraph("Summary of Alerts", sub2heading_style))
        data = [['Risk Level', 'Number of Alerts']] + [[level, str(count)] for level, count in summary.items()]
        summary_table = Table(data, colWidths=[2 * inch, 1.5 * inch])

        summary_severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        for i, (level, _) in enumerate(summary.items(), start=1):
            bg_color = summary_severity_colors.get(level, colors.white)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, i), (0, i), bg_color),
            ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 24))

        # Category Summary
        elements.append(Paragraph("Category Summary", sub2heading_style))
        data = [['Category', 'Number of Instances']] + [[category, str(count)] for category, count in category_summary.items()]
        category_table = Table(data, colWidths=[2 * inch, 1.5 * inch])

        category_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(category_table)
        elements.append(Spacer(1, 24))

        # Detailed Alerts Organized by Category
        elements.append(Paragraph("Alerts Organized by Category", sub2heading_style))

        # Severity color definitions for alerts
        severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}

        for result in detailed_results:
            category = result.get('type', 'Uncategorized')
            endpoint_or_target = result.get('endpoint', result.get('target_ip', 'N/A'))
            vulnerabilities = result.get('vulnerabilities', [])

            if category == 'Host Information':
                elements.append(Paragraph(f"{category}", subheading_style))
                url = result['details'].get('URL', 'N/A')
                elements.append(Paragraph(f"URL: {url}", normal_style))

                # Add Headers Information
                all_headers = result['details'].get('all_headers', {})
                elements.append(Paragraph("All Headers:", subheading_style))
                header_data = [[key, value] for key, value in all_headers.items()]
                header_table = Table(header_data, colWidths=[2 * inch, 4 * inch])
                header_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(header_table)
                elements.append(Spacer(1, 12))

                # Add Security Headers Information
                sec_headers = result['details'].get('security_headers', {})
                elements.append(Paragraph("Security Headers:", subheading_style))
                sec_header_data = [[key, value['status'], value['severity'], value['description']] for key, value in sec_headers.items()]
                sec_header_table = Table(sec_header_data, colWidths=[1.5 * inch, 1 * inch, 1 * inch, 3.5 * inch])
                sec_header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(sec_header_table)
                elements.append(Spacer(1, 12))

            elif vulnerabilities:
                elements.append(Paragraph(f"{category} (Endpoint/IP: {endpoint_or_target})", subheading_style))
                data = [['Issue', 'Description', 'Severity']]

                for vuln in vulnerabilities:
                    issue = Paragraph(vuln.get('issue', 'N/A'), normal_style)
                    description = Paragraph(vuln.get('description', 'N/A'), normal_style)
                    severity = vuln.get('severity', 'N/A')

                    data.append([issue, description, severity])

                alerts_table = Table(data, colWidths=[1.5 * inch, 4 * inch, 1.5 * inch])
                alerts_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))

                for i, vuln in enumerate(vulnerabilities, start=1):
                    bg_color = severity_colors.get(vuln.get('severity', 'N/A'), colors.white)
                    alerts_table.setStyle(TableStyle([
                        ('BACKGROUND', (2, i), (2, i), bg_color),
                    ]))

                elements.append(alerts_table)
                elements.append(Spacer(1, 12))

        # Build the PDF
        doc.build(elements)
        print(f"PDF report saved to {file_path}")
    except Exception as e:
        print(f"Failed to generate PDF report: {e}")
