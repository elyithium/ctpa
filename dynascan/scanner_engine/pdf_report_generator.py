import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

def generate_reportlab_pdf(site, summary, alerts, file_path='/app/reports/vulnerability_report.pdf'):
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

        # Align the summary table to the left
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

        elements.append(summary_table)
        elements.append(Spacer(1, 24))

        # Detailed Alerts
        elements.append(Paragraph("Alerts", sub2heading_style))
        data = [['Issue', 'Description', 'Severity', 'Endpoint']]
        severity_colors = {'High': colors.red, 'Medium': colors.orange, 'Low': colors.yellow, 'Informational': colors.blue}

        for alert in alerts:
            issue = Paragraph(alert['issue'], normal_style)
            description = Paragraph(alert['description'], normal_style)
            severity = alert['severity']
            endpoint = Paragraph(alert['endpoint'], normal_style)

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
        for i, alert in enumerate(alerts, start=1):
            bg_color = severity_colors.get(alert['severity'], colors.white)
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (2, i), (2, i), bg_color),
            ]))

        elements.append(alerts_table)

        # Build the PDF
        doc.build(elements)
        print(f"PDF report saved to {file_path}")
    except Exception as e:
        print(f"Failed to generate PDF report: {e}")
