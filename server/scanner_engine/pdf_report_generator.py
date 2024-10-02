from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak

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
        elements.append(Paragraph(f"Site: {site}", heading_style))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S')}", sub2heading_style))
        elements.append(Spacer(1, 12))

        # Summary of Alerts
        elements.append(Paragraph("Summary of Alerts", subheading_style))
        data = [[Paragraph('Risk Level', normal_style), Paragraph('Number of Alerts', normal_style)]]
        for level, count in summary.items():
            data.append([Paragraph(level, normal_style), Paragraph(str(count), normal_style)])

        summary_table = Table(data, colWidths=[2 * inch, 1.5 * inch], hAlign='LEFT')

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
        elements.append(Paragraph("Category Summary", subheading_style))
        data = [[Paragraph('Category', normal_style), Paragraph('Number of Instances', normal_style)]]
        for category, count in category_summary.items():
            data.append([Paragraph(category, normal_style), Paragraph(str(count), normal_style)])

        category_table = Table(data, colWidths=[2 * inch, 1.5 * inch], hAlign='LEFT')

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
        elements.append(PageBreak())
        # Detailed Alerts Organized by Category

        # Severity color definitions for alerts
        severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}

        for result in detailed_results:
            category = result.get('type', 'Uncategorized')
            endpoint_or_target = result.get('endpoint', result.get('target_ip', 'N/A'))
            vulnerabilities = result.get('vulnerabilities', [])

            if category == 'Host Information':
                # Add Headers Information
                all_headers = result['details'].get('all_headers', {})
                elements.append(Paragraph("All Headers:", subheading_style))
                header_data = [[Paragraph(key, normal_style), Paragraph(value, normal_style)] for key, value in all_headers.items()]
                header_table = Table(header_data, colWidths=[2 * inch, 4 * inch], hAlign='LEFT')
                header_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(header_table)
                elements.append(Spacer(1, 12))

                # Add Security Headers Information
                sec_headers = result['details'].get('security_headers', {})
                elements.append(Paragraph("Security Headers:", subheading_style))

                # Define column headers separately
                sec_header_data = [[
                    Paragraph('Header', normal_style),
                    Paragraph('Status', normal_style),
                    Paragraph('Severity', normal_style),
                    Paragraph('Description', normal_style)
                ]]

				# Add the data rows
                for key, value in sec_headers.items():
                    sec_header_data.append([
                        Paragraph(key, normal_style),
                        Paragraph(value.get('status', 'N/A'), normal_style),
                        Paragraph(value.get('severity', 'N/A'), normal_style),
                        Paragraph(value.get('description', 'N/A'), normal_style)
                    ])

                sec_header_table = Table(sec_header_data, colWidths=[1.9 * inch, 0.8 * inch, 0.8 * inch, 3.5 * inch])
                sec_header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(sec_header_table)
                elements.append(Spacer(1, 12))


            # Handle Open Ports separately
            elif category == 'Open Ports':
                elements.append(Paragraph(f"{category}<br/>Endpoint/IP: {endpoint_or_target}", subheading_style))
                port_data = [[Paragraph('Port', normal_style), Paragraph('Issue', normal_style), Paragraph('Description', normal_style), Paragraph('Severity', normal_style)]]

                for port_info in vulnerabilities:
                    port = Paragraph(str(port_info['port']), normal_style)
                    for vuln in port_info.get('vulnerabilities', []):
                        issue = Paragraph(vuln.get('issue', 'N/A'), normal_style)
                        description = Paragraph(vuln.get('description', 'N/A'), normal_style)
                        severity = vuln.get('severity', 'N/A')

                        port_data.append([port, issue, description, severity])

                port_table = Table(port_data, colWidths=[1 * inch, 1.5 * inch, 3 * inch, 1.5 * inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))


                row_index = 1
                for port_info in vulnerabilities:
                    for vuln in port_info.get('vulnerabilities', []):
                        bg_color = severity_colors.get(vuln.get('severity', 'N/A'), colors.white)
                        port_table.setStyle(TableStyle([
                            ('BACKGROUND', (3, row_index), (3, row_index), bg_color),
                        ]))
                        row_index += 1


                elements.append(port_table)

            elif category == "Cryptographic Failures Within Endpoint":
                elements.append(Paragraph(f"{category}<br/>Endpoint/IP: {endpoint_or_target}", subheading_style))
                data = [[Paragraph('Issue', normal_style), Paragraph('Description', normal_style), Paragraph('Severity', normal_style), Paragraph('Details', normal_style)]]

                for vuln in vulnerabilities:
                    issue = Paragraph(vuln.get('issue', 'N/A'), normal_style)
                    description = Paragraph(vuln.get('description', 'N/A'), normal_style)
                    severity = vuln.get('severity', 'N/A')

                    # Check if details is a dictionary, and convert it to a string or use 'N/A'
                    details_value = vuln.get('details', 'N/A')
                    if isinstance(details_value, dict):
                        details_str = ', '.join([f"{k}: {v}" for k, v in details_value.items()])
                    else:
                        details_str = details_value

                    details = Paragraph(details_str, normal_style)

                    data.append([issue, description, severity, details])

                alerts_table = Table(data, colWidths=[1 * inch, 1.5 * inch, 3 * inch, 1.5 * inch])
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

            elif vulnerabilities:
                elements.append(Paragraph(f"{category}<br/>Endpoint/IP: {endpoint_or_target}", subheading_style))
                data = [[Paragraph('Issue', normal_style), Paragraph('Description', normal_style), Paragraph('Severity', normal_style)]]

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
