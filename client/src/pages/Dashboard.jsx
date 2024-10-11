import React, { useState } from 'react';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import { styled } from '@mui/material/styles';
import Snackbar from '@mui/material/Snackbar';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import api from '../api';
import { useNavigate } from 'react-router-dom';

// Full Screen Paper component styling
const FullScreenPaper = styled(Paper)({
	minHeight: '100vh',
	display: 'flex',
	flexDirection: 'column',
	padding: '3rem',
	backgroundColor: '#171A21',
	color: '#78FBC9',
	justifyContent: 'center'
});

// Main Dashboard Component
const Dashboard = () => {
	// State for managing input URL, scanner type, and UI feedback elements
	const [url, setUrl] = useState('');
	const [scannerType, setScannerType] = useState('OWASP'); // Default scanner type
	const [openSnackbar, setOpenSnackbar] = useState(false);
	const [showErrorAlert, setShowErrorAlert] = useState(null);
	const [loading, setLoading] = useState(false);
	const [scanPhase, setScanPhase] = useState('Preparing Scan...');
	const navigate = useNavigate();

	// Handle Scan initiation
	const handleScan = async () => {
		if (!url || !isValidURL(url)) {
			setShowErrorAlert('Please enter a valid URL.');
			setTimeout(() => {
				setShowErrorAlert(null);
			}, 5000);
			return;
		}

		setLoading(true);
		setScanPhase('Starting Scan...');

		try {
			setScanPhase('Scanning Endpoints...');
			const response = await api.post('/api/scan', { target: url, scannerType }, { timeout: 120000 });

			const reportId = response.data.report._id;

			setScanPhase('Finalizing...');
			if (reportId) {
				localStorage.setItem('latestReportId', reportId);
				navigate('/Reports/Reports');
			} else {
				setShowErrorAlert('Failed to obtain report ID. Please try again.');
			}
		} catch (error) {
			console.error('Error during scan:', error);
			setShowErrorAlert('An error occurred during the scan. Please try again.');
			setTimeout(() => {
				setShowErrorAlert(null);
			}, 5000);
		} finally {
			setLoading(false);
			setScanPhase('Complete');
		}
	};

	// URL validation function
	const isValidURL = (string) => {
		try {
			new URL(string);
			return true;
		} catch (_) {
			return false;
		}
	};

	// Close handlers for alert and snackbar
	const handleClose = () => {
		setShowErrorAlert(false);
		setOpenSnackbar(false);
	};

	return (
		<FullScreenPaper>
			<Container maxWidth="md">
				<Box paddingBottom={3}>
					<Typography variant="h4" gutterBottom>
						URL Security Audit
					</Typography>
					<Typography variant="body1" paragraph>
						Enter a URL for comprehensive security analysis. Select a scanner category and click the "Start Scan" button to initiate the process.
					</Typography>
				</Box>

				<Box paddingBottom={3}>
					<Typography variant="h6" gutterBottom>
						Enter URL
					</Typography>
					<TextField
						label="URL"
						variant="outlined"
						fullWidth
						value={url}
						onChange={(e) => setUrl(e.target.value)}
						error={!!showErrorAlert}
						helperText={showErrorAlert}
						sx={{ marginBottom: '1rem' }}
					/>

					{/* Dropdown for scanner type */}
					<FormControl fullWidth sx={{ marginBottom: '1rem' }}>
						<InputLabel id="scanner-type-label">Scanner Type</InputLabel>
						<Select
							labelId="scanner-type-label"
							id="scanner-type"
							value={scannerType}
							label="Scanner Type"
							onChange={(e) => setScannerType(e.target.value)}
						>
							<MenuItem value="Full Scan">Full Scan</MenuItem>
							<MenuItem value="Broken Access Control">Broken Access Control</MenuItem>
							<MenuItem value="Injection">Injection</MenuItem>
							<MenuItem value="Cryptographic Failures">Cryptographic Failures</MenuItem>
							<MenuItem value="Security Misconfiguration">Security Misconfiguration</MenuItem>
							<MenuItem value="Server-Side Request Forgery">Server-Side Request Forgery</MenuItem>
							<MenuItem value="Insecure Deserialization">Insecure Deserialization</MenuItem>
							<MenuItem value="Reconnaissance">Reconnaissance</MenuItem>
						</Select>
					</FormControl>

					{/* Scan button */}
					<Box display="flex" justifyContent="center">
						<Button
							variant="contained"
							color="primary"
							onClick={handleScan}
							disabled={loading}
							startIcon={loading ? <CircularProgress size={24} /> : null}
						>
							{loading ? 'Scanning...' : 'Start Scan'}
						</Button>
					</Box>

					{/* Display scan phase */}
					{loading && (
						<Box mt={2} display="flex" justifyContent="center">
							<Typography variant="body2" color="textSecondary">
								{scanPhase}
							</Typography>
						</Box>
					)}
				</Box>

				<Snackbar
					anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
					open={openSnackbar}
					autoHideDuration={6000}
					onClose={handleClose}
					message={`Scan Complete for ${url}`}
				/>
			</Container>
		</FullScreenPaper>
	);
};

export default Dashboard;
