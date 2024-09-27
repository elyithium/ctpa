import React from 'react';
import { Container, Typography, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Box } from '@mui/material';
import { styled } from '@mui/system';

// Styled components
const FullScreenPaper = styled(Paper)({
	minHeight: '100vh',
	display: 'flex',
	flexDirection: 'column',
	alignItems: 'center',
	padding: '3rem',
	backgroundColor: '#171A21',
	color: '#78FBC9',
});

const StyledTableContainer = styled(TableContainer)({
	marginTop: '20px',
	marginBottom: '20px',
	backgroundColor: '#1c1f26',
	color: '#ffffff'
});

const StyledTableCell = styled(TableCell)({
	color: '#ffffff',
	fontSize: '16px',
	borderBottom: '1px solid #78FBC9'
});

// Sample data for the table
const teamMembers = [
	{ handle: 'DynaLead', name: 'Yashvir Chaudhary', contact: 'yashchaudhary@student.swin.edu.au', role: 'Team Leader' },
	{ handle: 'DynaDesign', name: 'Gurjodh Thukral', contact: 'gthukral@student.swin.edu.au', role: 'Security Architect' },
	{ handle: 'Kartik2123', name: 'Kartikeya Gupta', contact: 'kartikeya@student.swin.edu.au', role: 'Developer and Proofreading' },
	{ handle: 'Anuj2022', name: 'Anuj Kumar', contact: 'anuj.kumar@student.swin.edu.au', role: 'UI/UX Developer' },
	{ handle: 'Mohammed.ali', name: 'Mohammed Ali', contact: 'mohammed.ali@student.swin.edu.au', role: 'Security Architect' },
	{ handle: 'Jones-4113', name: 'Ali Mohamadi Jokar', contact: 'jokarali@student.swin.edu.au', role: 'Risk Assessor' },
];

const TeamPage = () => {
	return (
		<FullScreenPaper>
			<Container maxWidth="lg">
				{/* Title Section */}
				<Typography variant="h2" gutterBottom>
					DynaScan About Us
				</Typography>
				<Typography variant="h5" gutterBottom>
					We are DynaScan, a team of Swinburne Students...
				</Typography>
				<Typography variant="h6" gutterBottom>
					These are the people who are currently spending the most time making Dyna better for everyone:
				</Typography>

				{/* Table Section */}
				<StyledTableContainer component={Paper}>
					<Table>
						<TableHead>
							<TableRow>
								<StyledTableCell>Handle</StyledTableCell>
								<StyledTableCell>Name</StyledTableCell>
								<StyledTableCell>Contact</StyledTableCell>
								<StyledTableCell>Role</StyledTableCell>
							</TableRow>
						</TableHead>
						<TableBody>
							{teamMembers.map((member, index) => (
								<TableRow key={index}>
									<StyledTableCell>{member.handle}</StyledTableCell>
									<StyledTableCell>{member.name}</StyledTableCell>
									<StyledTableCell>
										<a href={`mailto:${member.contact}`} style={{ color: '#78FBC9', textDecoration: 'none' }}>
											{member.contact}
										</a>
									</StyledTableCell>
									<StyledTableCell>{member.role}</StyledTableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				</StyledTableContainer>

				{/* Footer Section */}
				<Box marginTop={4}>
					<Typography variant="body2" color="textSecondary">
						Version 1.0
					</Typography>
				</Box>
			</Container>
		</FullScreenPaper>
	);
};

export default TeamPage;
