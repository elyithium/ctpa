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
import api from '../api';
import { useNavigate } from 'react-router-dom';

// Full Screen Paper component styling
const FullScreenPaper = styled(Paper)({
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    padding: '3rem',
    backgroundColor: '#898952',
    color: '#ffffff',
    justifyContent: 'center'
});

// Main Dashboard Component
const Dashboard = () => {
    // State to manage input URL, snackbar visibility, error alert, and loading state
    const [url, setUrl] = useState('');
    const [openSnackbar, setOpenSnackbar] = useState(false);
    const [showErrorAlert, setShowErrorAlert] = useState(null);
    const [loading, setLoading] = useState(false);
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
        try {
            const response = await api.post('/api/scan', { target: url });
            const reportId = response.data.report._id;
            //console.log(reportId);
            localStorage.setItem('latestReportId', reportId);
            localStorage.setItem('scanResults', JSON.stringify(response.data.report.vulnerabilities));
            setOpenSnackbar(true);
            navigate('/Reports/Reports');
        } catch (error) {
            console.error('Error during scan:', error);
            setShowErrorAlert('An error occurred during the scan. Please try again.');
            setTimeout(() => {
                setShowErrorAlert(null);
            }, 5000);
        } finally {
            setLoading(false);
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
            <Container maxWidth="lg">
                <Box paddingBottom={3}>
                    <Typography variant="h4" gutterBottom>
                        URL Security Audit
                    </Typography>
                    <Typography variant="body1" paragraph>
                        Enter a URL for comprehensive security analysis. After entering the URL, click the "Start Scan" button to begin the analysis.
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
                </Box>

                <Snackbar
                    anchorOrigin={{
                        vertical: 'bottom',
                        horizontal: 'left',
                    }}
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
