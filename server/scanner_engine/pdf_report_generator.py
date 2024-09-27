import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Indenter

def generate_reportlab_pdf(site, summary, category_summary, detailed_results, file_path='./reports/vulnerability_report.pdf'):
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
    except Exception as e:
        print(f"Failed to create directory: {e}")
        return

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

        # Risk level colors including Informational
        summary_severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}

        # Align the summary table with the title above (left-aligned)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),  # Align left for the rest of the table
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        # Apply color based on severity for the Risk Level column only
        for i, (level, _) in enumerate(summary.items(), start=1):
            bg_color = summary_severity_colors.get(level, colors.white)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, i), (0, i), bg_color),
            ]))

        # Indent to align with the title
        elements.append(Indenter(left=20))
        elements.append(summary_table)
        elements.append(Indenter(left=-20))  # Reset indentation
        elements.append(Spacer(1, 24))

        # Category Summary (Left Aligned with Title)
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

        elements.append(Indenter(left=20))  # Indent category table
        elements.append(category_table)
        elements.append(Indenter(left=-20))  # Reset indentation
        elements.append(Spacer(1, 24))

        # Detailed Alerts Organized by Category
        elements.append(Paragraph("Alerts Organized by Category", sub2heading_style))

        # Severity color definitions for alerts
        severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}

        for result in detailed_results:
            category = result.get('type', 'Uncategorized')
            vulnerabilities = result.get('vulnerabilities', [])

            if vulnerabilities:
                elements.append(Paragraph(f"{category}", subheading_style))
                data = [['Issue', 'Description', 'Severity', 'Endpoint']]

                for vuln in vulnerabilities:
                    issue = Paragraph(vuln.get('issue', 'N/A'), normal_style)
                    description = Paragraph(vuln.get('description', 'N/A'), normal_style)
                    severity = vuln.get('severity', 'N/A')
                    endpoint = Paragraph(vuln.get('endpoint', 'N/A'), normal_style)

                    data.append([issue, description, severity, endpoint])

                alerts_table = Table(data, colWidths=[1.5 * inch, 2.5 * inch, 1 * inch, 2 * inch])
                alerts_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))

                # Apply color based on severity for the Severity column in Alerts
                for i, vuln in enumerate(vulnerabilities, start=1):
                    bg_color = severity_colors.get(vuln.get('severity', 'N/A'), colors.white)
                    alerts_table.setStyle(TableStyle([
                        ('BACKGROUND', (2, i), (2, i), bg_color),
                    ]))

                elements.append(Indenter(left=20))  # Indent alert tables
                elements.append(alerts_table)
                elements.append(Indenter(left=-20))  # Reset indentation
                elements.append(Spacer(1, 12))

        # Build the PDF
        doc.build(elements)
        print(f"PDF report saved to {file_path}")
    except Exception as e:
        print(f"Failed to generate PDF report: {e}")
