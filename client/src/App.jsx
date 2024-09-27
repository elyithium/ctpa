import React from 'react';
import Homepage from './pages/HomePage';
import Dashboard from './pages/Dashboard';
import Reports from './pages/Reports';
import AboutUs from './pages/AboutUs';
import Guide from './pages/Guide';
import Container from '@mui/material/Container';
import { Routes, Route, BrowserRouter as Router, Navigate } from 'react-router-dom';
import Searchbar from './components/Searchbar';
import Footer from './components/Footer';
import './styles/App.css';
import {  CssBaseline,Paper, createTheme, ThemeProvider } from '@mui/material';
import { blue } from '@mui/material/colors';

export default function App() {
    const theme = createTheme({
        palette: {
            mode:"dark",
            background: {
                default: "#171A21", // Set the background color for the entire app
                paper: "#171A21"    // Set the background color for Paper components if needed
            },
            primary: {
            main : blue[500],
            contrastText: '#fff',
          },
          },
        });
    return (
        <Router>
            <div className="App">
            <CssBaseline />
            {/* Top search bar component */}
                <Searchbar />
                {/* Main app theme provider with custom theme */}
                <ThemeProvider theme={theme}>
                    {/* Central content container */}
                    <Paper variant="outlined" style={{ margin: '0 auto', maxWidth: 'lg', padding: '1rem' }}>
                        <Container style={{ paddingTop: 64 }}>
                            {/* Main routing for the application */}
                            <Routes>
                                <Route path="/" element={<Navigate to="/Homepage/HomePage" />} />
                                <Route path="/Homepage/Homepage" element={<Homepage />} />
                                <Route path="/Dashboard/Dashboard" element={<Dashboard />} />
                                <Route path="/Reports/Reports" element={<Reports />} />
								<Route path="/AboutUs/AboutUs" element={<AboutUs />} />
								<Route path="/Guide/Guide" element={<Guide />} />
                            </Routes>
                        </Container>
                    </Paper>
                </ThemeProvider>
                {/* Footer component */}
                <Footer />
            </div>
        </Router>
    );
}
