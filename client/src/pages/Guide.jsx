import React from 'react';
import { Paper, Typography, Button, Container, Accordion, AccordionSummary, AccordionDetails } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { styled } from '@mui/material/styles';
import '../styles/App.css';

// Styling the Paper component to take the full height of the screen
const FullScreenPaper = styled(Paper)({
	minHeight: '100vh',
	display: 'flex',
	flexDirection: 'column',
	padding: '3rem',
	backgroundColor: '#171A21',
	color: '#78FBC9'
});

const PreviousReports = () => {
	return (
		<FullScreenPaper>
			<Container className="container">
				{/* Header Section */}
				<Typography variant="h2" className="header" paddingBottom={'1rem'}>
					DynaScan User Manual
				</Typography>
				<Typography variant="body1" className="sub-header" paddingBottom={'1rem'}>
					Welcome to DynaScan DAST User Guide. DynaScan is an easy-to-use integrated penetration testing tool for finding vulnerabilities in web applications.
					<br />
					<br />
					DynaScan allows you to enter a URL which will first spider and then active scan. For a more in-depth test, you should explore your application using your browser.
				</Typography>

				{/* Download Button */}
				<Button className="download-button" variant="contained" >
					Download User Guide
				</Button>

				{/* See Also Section */}
				<Typography variant="h4" className="section-title" paddingBottom={'1rem'} paddingTop={'4rem'}>
					See also
				</Typography>

				{/* Accordion for different topics */}
				<div className="accordion-container">
					<Accordion className="accordion">
						<AccordionSummary expandIcon={<ExpandMoreIcon />} className="accordion-summary">
							Configuring
						</AccordionSummary>
						<AccordionDetails>
							<Typography>
								Detailed instructions on how to configure DynaScan for your specific needs.
							</Typography>
						</AccordionDetails>
					</Accordion>
					<Accordion className="accordion">
						<AccordionSummary expandIcon={<ExpandMoreIcon />} className="accordion-summary">
							Introduction
						</AccordionSummary>
						<AccordionDetails>
							<Typography>
								Learn about the features and capabilities of DynaScan, and how to get started with the tool.
							</Typography>
						</AccordionDetails>
					</Accordion>
					<Accordion className="accordion">
						<AccordionSummary expandIcon={<ExpandMoreIcon />} className="accordion-summary">
							Features
						</AccordionSummary>
						<AccordionDetails>
							<Typography>
								Explore the features available in DynaScan and how they can help you improve the security of your web applications.
							</Typography>
						</AccordionDetails>
					</Accordion>
					<Accordion className="accordion">
						<AccordionSummary expandIcon={<ExpandMoreIcon />} className="accordion-summary">
							Scanner Rules
						</AccordionSummary>
						<AccordionDetails>
							<Typography>
								Get detailed information on how to configure and customize the scanning rules of DynaScan.
							</Typography>
						</AccordionDetails>
					</Accordion>
				</div>
			</Container>
		</FullScreenPaper>
	);
};

export default PreviousReports;
