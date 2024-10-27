import axios from 'axios';
import { render, screen } from '@testing-library/react';
import App from '../App'; // Adjust path as necessary

test('Test API Response Data Structure', async () => {
    const response = await axios.post('http://localhost:5000/api/scan', {
        target: 'http://127.0.0.1:8080',
        scannerType: 'Full Scan'
    });
    const data = response.data;

    // Check the response structure
    expect(data).toHaveProperty('report');
    expect(data.report).toHaveProperty('vulnerabilities');
    // Add more checks as needed
});
