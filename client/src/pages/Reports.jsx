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
	backgroundColor: '#171A21',
	color: '#78FBC9',
});

const Reports = () => {
	const [report, setReport] = useState(null);

	useEffect(() => {
		const reportId = localStorage.getItem('latestReportId');
		console.log(`Report ID retrieved from localStorage: ${reportId}`);
		if (reportId) {
			// Fetch the report data only if a new report ID exists in localStorage
			axios.get(`/api/report_data/${reportId}`)
				.then(response => {
					console.log('Report data fetched from backend:', response.data.report);
					setReport(response.data.report);
				})
				.catch(error => {
					console.error('Error fetching report:', error);
				});
		} else {
			console.log('No report ID found in localStorage');
		}

		const clearStorage = () => {
			localStorage.removeItem('latestReportId');
		};

		window.addEventListener('beforeunload', clearStorage);

		return () => {
			setReport(null);
			window.removeEventListener('beforeunload', clearStorage);
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
			case 'Informational':
				return '#0000FF'; // Blue
			case 'NONE':
			default:
				return '#FFFFFF'; // White
		}
	};

	// Render host information
	const renderHostInformation = (hostInfo) => (
		<Grid container spacing={3}>
			<Grid item xs={12}>
				<Typography><br/><strong>URL:</strong> {hostInfo.details?.URL}</Typography>
				<Typography><strong>Response Headers:</strong></Typography>
				{Object.entries(hostInfo.details?.all_headers || {}).map(([header, value], index) => (
					<Typography key={index}>{header}: <i>{value}</i></Typography>
				))}
				<Typography><strong><br/>Security Headers:</strong></Typography>
				{Object.entries(hostInfo.details?.security_headers || {}).map(([header, details], index) => (
					<Typography key={index}>
						{header}: {details.status} ({details.severity} severity)
					</Typography>
				))}
			</Grid>
		</Grid>
	);

	// Render Open Ports
	const renderOpenPorts = (openPorts) => (
		<Grid container spacing={3}>
			<Grid item xs={12}>
				<Typography><strong>Target IP:</strong> {openPorts.target_ip}</Typography>
				{openPorts.vulnerabilities.map((portInfo, index) => (
					<div key={index}>
						<Typography><strong>Port:</strong> {portInfo.port}</Typography>
						{portInfo.vulnerabilities.map((vuln, subIndex) => (
							<div key={subIndex}>
								<Typography><strong>Issue:</strong> {vuln.issue}</Typography>
								<Typography><strong>Description:</strong> {vuln.description}</Typography>
								<Typography><strong>Severity:</strong> {vuln.severity}</Typography>
							</div>
						))}
					</div>
				))}
			</Grid>
		</Grid>
	);

	// Render other vulnerability details dynamically
	const renderVulnerabilityDetails = (vuln) => (
		<Grid container spacing={3}>
			{vuln.severity && (
				<Grid item xs={12} md={4}>
					<Typography><strong>Severity:</strong> {vuln.severity}</Typography>
				</Grid>
			)}
			{vuln.description && (
				<Grid item xs={12} md={4}>
					<Typography><strong>Description:</strong> {vuln.description}</Typography>
				</Grid>
			)}
			{vuln.endpoint && (
				<Grid item xs={12} md={4}>
					<Typography><br/><strong>Location:</strong> {vuln.endpoint}</Typography>
				</Grid>
			)}
			{/* Handle individual issues inside "vulnerabilities" if it exists */}
			{vuln.vulnerabilities && vuln.vulnerabilities.map((subVuln, subIndex) => (
				<Grid item xs={12} key={subIndex}>
					<Typography><strong>Issue:</strong> {subVuln.issue}</Typography>
					<Typography><strong>Description:</strong> {subVuln.description}</Typography>
					<Typography><strong>Severity:</strong> {subVuln.severity}</Typography>
				</Grid>
			))}
		</Grid>
	);

	// Download button handler
	const handleDownload = async () => {
		const reportId = localStorage.getItem('latestReportId');
		if (reportId) {
			try {
				const response = await axios.get(`/api/reports/vulnerability_report_${reportId}.pdf`, {
					responseType: 'blob', // Important: Receive file as blob
				});
				const url = window.URL.createObjectURL(new Blob([response.data]));
				const link = document.createElement('a');
				link.href = url;
				link.setAttribute('download', `vulnerability_report_${reportId}.pdf`);
				document.body.appendChild(link);
				link.click();
				link.remove();
			} catch (error) {
				console.error("Failed to download the report:", error);
			}
		}
	};

	return (
		<FullScreenPaper sx={{ backgroundColor: '#20252B', color: '#78FBC9' }}>
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
						<Paper key={index} style={{ padding: '50px', marginBottom: '20px', }}>
							<Grid container spacing={3}>
								<Grid item xs={12}>
									<Typography
										variant="h5"
										gutterBottom
										style={{ color: getSeverityColor(vuln.severity || 'NONE') }}
									>
										<ErrorOutlineIcon color="secondary" /> Vulnerability Type: {vuln.type}
									</Typography>
									<Divider />
								</Grid>
								{/* Conditionally render based on vulnerability type */}
								{vuln.type === "Host Information" && renderHostInformation(vuln)}
								{vuln.type === "Open Ports" && renderOpenPorts(vuln)}
								{vuln.type !== "Host Information" && vuln.type !== "Open Ports" && renderVulnerabilityDetails(vuln)}
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
};

export default Reports;
