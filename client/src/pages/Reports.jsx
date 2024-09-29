import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Container, Typography, Paper, Grid, Divider, Button } from '@mui/material';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import { styled } from '@mui/material/styles';

// Styling the Paper component to take the full height of the screen
const FullScreenPaper = styled(Paper)({
	minHeight: '100vh',
	display: 'flex',
	flexDirection: 'column',
	padding: '3rem',
});

const Reports = () => {
	const [report, setReport] = useState(null);

	useEffect(() => {
		const reportId = localStorage.getItem('latestReportId');
		if (reportId) {
			axios.get(`/api/report_data/${reportId}`)
			.then(response => {
				// This response.data contains the JSON report details
					console.log(response.data.report);
					setReport(response.data.report);
				})
				.catch(error => {
					console.error('Error fetching report:', error);
				});
		} else {
			console.log('No report ID found in localStorage');
		}

		return () => {
			setReport(null);
		};
	}, []);

	const getSeverityColor = (severity) => {
		switch (severity) {
			case 'High':
				return '#FF0000'; // Red
			case 'Medium':
				return '#FFA500'; // Orange
			case 'Low':
				return '#FFFF00'; // Yellow
			case 'NONE':
			default:
				return '#FFFFFF'; // White
		}
	};

	// Download button handler
	const handleDownload = () => {
		const reportId = localStorage.getItem('latestReportId');
		if (reportId) {
			window.open(`/api/reports/vulnerability_report_${reportId}.pdf`, '_blank');
		}
	};

	return (
		<FullScreenPaper sx={{ backgroundColor: '#6BAA75', color: '#ffffff' }}>
			<Container>
				<Typography variant="h4" gutterBottom align="center">
					Analysis Results
				</Typography>

				{/* Display Target URL and Generated On Date */}
				{report && (
					<div>
						<Typography variant="h6" gutterBottom>
							<strong>Target:</strong> {report.target}
						</Typography>
						<Typography variant="h6" gutterBottom>
							<strong>Generated on:</strong> {new Date(report.createdAt).toLocaleString()}
						</Typography>
						<Divider sx={{ marginBottom: '20px' }} />
					</div>
				)}

				{/* Download Report Button */}
				{report && (
					<Button variant="contained" color="primary" onClick={handleDownload} sx={{ marginBottom: '20px' }}>
						Download PDF Report
					</Button>
				)}

				{report && report.vulnerabilities && report.vulnerabilities.length > 0 ? (
					report.vulnerabilities.map((vuln, index) => (
						<Paper key={index} style={{ padding: '20px', marginBottom: '20px' }}>
							<Grid container spacing={3}>
								<Grid item xs={12}>
									<Typography
										variant="h5"
										gutterBottom
										style={{ color: getSeverityColor(vuln.severity) }}
									>
										<ErrorOutlineIcon color="secondary" /> Vulnerability Type: {vuln.type}
									</Typography>
									<Divider />
								</Grid>
								<Grid item xs={12} md={4}>
									<Typography><strong>Severity:</strong> {vuln.severity}</Typography>
								</Grid>
								<Grid item xs={12} md={4}>
									<Typography><strong>Description:</strong> {vuln.description}</Typography>
								</Grid>
								<Grid item xs={12} md={4}>
									<Typography><strong>Location:</strong> {vuln.endpoint}</Typography>
								</Grid>
							</Grid>
						</Paper>
					))
				) : (
					<Typography align="center" style={{ marginTop: '20px' }}>
						No results available at the moment. Please upload a URL on the Dashboard page for analysis.
					</Typography>
				)}
			</Container>
		</FullScreenPaper>
	);
}

export default Reports;
