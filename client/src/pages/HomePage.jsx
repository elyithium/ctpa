import React from 'react';
import { Container, Typography, Button, Paper, Grid2 } from '@mui/material';
import { styled } from '@mui/system';
import '../styles/App.css';
import { useNavigate } from 'react-router-dom';

const FullScreenPaper = styled(Paper)({
	minHeight: '100vh',
	alignItems: 'center',
	justifyContent: 'center',
	padding: '2rem',
	backgroundColor: '#171A21',
	color: '#78FBC9',
	textAlign: 'center',
	maxWidth: '1400px'
});


const FeatureBox = styled(Paper)({
	padding: '3rem',
	paddingBottom: '6srem',
	backgroundColor: '#1c1f26',
	color: '#ffffff',
	textAlign: 'center',
	borderRadius: '8px',
	boxShadow: '0px 4px 8px rgba(0, 0, 0, 0.1)'
});

const HomePage = () => {
	const navigate = useNavigate();

	return (
		<FullScreenPaper>
			<Container className="container">
				{/* Title Section with ASCII Art, Description, and Scan Button */}
				<Grid2 container spacing={2} alignItems={'center'}>
					<Grid2 item xs={6} md={10} style={{ textAlign: 'center' }} size={7} alignContent={'center'}>
						<Typography variant="h5" gutterBottom className="logo">
							<pre style={{ textAlign: 'center', fontSize: '12px', color: '#78FBC9', lineHeight: '1.2', width: '550px', letterSpacing: '0.5px' }}>
								{`
.-=+*#%%@@@@@@@%%#*+=:
:=*#@@@@@@@@@@@@@@@@@@@@@@@@%#+-
-*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+.
-*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+.
.+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:
.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-
=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.
.#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=
-@@@@@@@@@@@@@@@@@@@@@@@@%#********#%%@@@@@@@@@@@@@@@@@@@@@@@#.
+@@@@@@@@@@@@@@@@@@@@@@@%##########*****%@@@@@@@@@@@@@@@@@@@@@@%.
=@@@@@@@@@@@@@@@@@@@@@@%*************+++==+%@@@@@@@@@@@@@@@@@@@@@%.
-@@@@@@@@@@@@@@@@@@@@@@#**************+====--%@@@@@@@@@@@@@@@@@@@@@#
.@@@@@@@@@@@@@@@@@@@@@@%*****************==---=@@@@@@@@@@@@@@@@@@@@@@+
*@@@@@@@@@@@@@@@@@@@@@@%*****************+-----%@@@@@@@@@@@@@@@@@@@@@@.
.@@@@@@@@@@@@@@@@@@@@@@@%*****************=-----@@@@@@@@@@@@@@@@@@@@@@@+
=@@@@@@@@@@@@@@@@@@@@@@@@##*****########*+---::+@@@@@@@@@@@@@@@@@@@@@@@#
*@@@@@@@@@@@@@@@@@@@@@@@@%**++++++**+++=-:::::-@@@@@@@@@@@@@@@@@@@@@@@@@.
#@@@@@@@@@@@@@@@@@@@@@@@@@@*=====------:::::-+@@@@@@@@@%%%%@#@@@@@@@@@@@@@:
#@@@@@@@@@@@@%@%@%%%@@@@@@@@%*==------::::=*@@@@@@@@@%%%%@#@@@@@@@@@@@@@:
*@@@@@@@@@@@@%%%@%%%@@@@@@@@@@@@******++#@@@@@@@@@@@@%%%#%#@@@@@@@@@@@@@.
=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%
.@@@@#-----=#@##@@@##%%##@@%#%@@####@@@%####%@@#*#%@@%###@@%##@@@##@@@@+
*@@@*..%%*..+#..*-.=@=..-%+.-@%..:.#@=.:===%%:.-:+@@..:.*@*..:##..@@@@:
.@@@#--@@@=-*@@+--%@@*-+=-=-+@+-+*-=@%++===*#-+@@@@+-=#--%#-=*-=--@@@+
-@@#+++++*#@@@%+*@@@#+#@#++*%++**++##++++*%@**++#%++***+*%+*@%*++@@%
+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.
+@@@@@@@@@@@@@@@@@@@@@@@@@@%%%@#@#%%#@@@@@@@@@@@@@@@@@@@@@@@@@@%.
=@@@@@@@@@@@@@@@@@@@@@@@@@#%###%*#@#@@@@@@@@@@@@@@@@@@@@@@@@@#.
.%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+
+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:
.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-.
.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-.
-#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+.
.=*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+:
:=*%@@@@@@@@@@@@@@@@@@@@@@@@@#+-
:-+*##%%@@@@@@@%%#*+=-.
                                `}
							</pre>
						</Typography>
					</Grid2>
					<Grid2 item xs={12} md={6} className="text-block" size={5} marginBottom={'1rem'}>
						<Typography variant="h4" gutterBottom marginBottom={'1rem'}>
							DYNASCAN
						</Typography>
						<Typography variant="h6" gutterBottom lineHeight={'1.2'} padding={'10px'}>
							@scanner:~$ Our Web Application Security Scanner offers an advanced, offline solution for
							detecting and assessing vulnerabilities in web applications. Utilize our tool to
							safely test and monitor your applications, ensuring comprehensive protection
							with detailed vulnerability reports and real-time traffic analysis.
						</Typography>
						<Button
							variant="contained"
							backgroundColor="#828282"
							className="button"
							margin='20px'
							onClick={() => navigate('/Dashboard/Dashboard')}
						>
							Scan Now
						</Button>
					</Grid2>
				</Grid2>

				{/* Feature Boxes */}
				<Grid2 container spacing={3} justifyContent="center" className="feature-container" paddingTop={'10rem'} paddingBottom={'5rem'}>
					<Grid2 item xs={12} md={4} size={4}>
						<FeatureBox className="feature-box">
							<Typography variant="h5">Reporting Made Easy</Typography>
							<Typography variant="body1" paddingBottom={'1rem'}>
								DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
							</Typography>
							<Button variant="contained" className="button">Learn More</Button>
						</FeatureBox>
					</Grid2>

					<Grid2 item xs={12} md={4} size={4}>
						<FeatureBox className="feature-box">
							<Typography variant="h5">Automate with Dyna</Typography>
							<Typography variant="body1" paddingBottom={'1rem'}>
								DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
							</Typography>
							<Button variant="contained" className="button">Learn More</Button>
						</FeatureBox>
					</Grid2>

					<Grid2 item xs={12} md={4} size={4}>
						<FeatureBox className="feature-box">
							<Typography variant="h5">About the Tool</Typography>
							<Typography variant="body1" paddingBottom={'1rem'}>
								DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
							</Typography>
							<Button variant="contained" className="button">Learn More</Button>
						</FeatureBox>
					</Grid2>
				</Grid2>
			</Container>
		</FullScreenPaper>
	);
};

export default HomePage;
