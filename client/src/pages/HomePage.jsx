import React from 'react';
import { Container, Box, Typography, Button, Grid, Paper } from '@mui/material';
import { styled } from '@mui/system';
import { useNavigate } from 'react-router-dom';

const FullScreenPaper = styled(Paper)({
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '2rem',
    backgroundColor: '#171A21',
    color: '#78FBC9',
    textAlign: 'center'
});

const FeatureBox = styled(Paper)({
    padding: '2rem',
    backgroundColor: '#1c1f26',
    color: '#ffffff',
    textAlign: 'center'
});

const HomePage = () => {
    const navigate = useNavigate();

    return (
        <FullScreenPaper>
            <Container>
                {/* Title Section with ASCII Art, Description, and Scan Button */}
                <Grid container alignItems="center" justifyContent="center" spacing={3}>
                    <Grid item xs={12} md={6} style={{ textAlign: 'center' }}>
                        <Typography variant="h5" gutterBottom>
                            <pre style={{ textAlign: 'center', fontSize: '10px', color: '#78FBC9' }}>
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
.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-
.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-
-#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+.
.=*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+:
:=*%@@@@@@@@@@@@@@@@@@@@@@@@@#+-
:-+*##%%@@@@@@@%%#*+=-.
`}
                            </pre>
                        </Typography>
                    </Grid>
                    <Grid item xs={12} md={6} style={{ textAlign: 'center' }}>
                        <Grid item xs={12} md={6} style={{ textAlign: 'center' }}>
                        <Typography variant="h4" gutterBottom>
                            DYNASCAN
                        </Typography>
                        <Typography variant="h6" gutterBottom>
                            @scanner:~$ Our Web Application Security Scanner offers an advanced, offline solution for
                            detecting and assessing vulnerabilities in web applications. Utilize our tool to
                            safely test and monitor your applications, ensuring comprehensive protection
                            with detailed vulnerability reports and real-time traffic analysis.
                        </Typography>
                    </Grid>
                        <Button
                            variant="contained"
                            color="secondary"
                            sx={{ backgroundColor: '#6883BA' }}
                            onClick={() => navigate('/Dashboard/Dashboard')}
                        >
                            Scan Now
                        </Button>
                    </Grid>
                </Grid>

                {/* Feature Boxes */}
                <Grid container spacing={3} justifyContent="center" sx={{ marginTop: '2rem' }}>
                    <Grid item xs={12} md={4}>
                        <FeatureBox>
                            <Typography variant="h5">Reporting Made Easy</Typography>
                            <Typography variant="body1">
                                DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
                            </Typography>
                            <Button variant="contained" sx={{ marginTop: '1rem', backgroundColor: '#6883BA' }}>Learn More</Button>
                        </FeatureBox>
                    </Grid>

                    <Grid item xs={12} md={4}>
                        <FeatureBox>
                            <Typography variant="h5">Automate with Dyna</Typography>
                            <Typography variant="body1">
                                DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
                            </Typography>
                            <Button variant="contained" sx={{ marginTop: '1rem', backgroundColor: '#6883BA' }}>Learn More</Button>
                        </FeatureBox>
                    </Grid>

                    <Grid item xs={12} md={4}>
                        <FeatureBox>
                            <Typography variant="h5">About the Tool</Typography>
                            <Typography variant="body1">
                                DynaScan provides a range of options for security automation. Check out the automation docs to start automating!
                            </Typography>
                            <Button variant="contained" sx={{ marginTop: '1rem', backgroundColor: '#6883BA' }}>Learn More</Button>
                        </FeatureBox>
                    </Grid>
                </Grid>
            </Container>
        </FullScreenPaper>
    );
};

export default HomePage;
