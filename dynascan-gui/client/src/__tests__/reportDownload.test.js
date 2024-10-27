import { render, screen, fireEvent } from '@testing-library/react';
import Reports from '../Reports'; // Adjust the import according to your structure
import axios from '../api'; // Ensure axios is correctly mocked

jest.mock('../../api');

beforeEach(() => {
    // Mock the localStorage
    localStorage.setItem('latestReportId', '123');

    // Mock the API response
    axios.get.mockImplementation((url) => {
        if (url === '/api/report_data/123') {
            return Promise.resolve({ data: { report: { target: 'http://example.com', createdAt: Date.now(), vulnerabilities: [] } } });
        }
        return Promise.reject(new Error('Not Found'));
    });

    // Mock the download response
    axios.get.mockImplementation((url) => {
        if (url === '/api/reports/vulnerability_report_123.pdf') {
            return Promise.resolve(new Blob(['mocked pdf content'], { type: 'application/pdf' }));
        }
        return Promise.reject(new Error('Not Found'));
    });
});

test('Assess Report Download Functionality', async () => {
    render(<Reports />); // Render the Reports component

    // Wait for the report to be fetched and the button to appear
    const downloadButton = await screen.findByText(/Download PDF Report/i);
    expect(downloadButton).toBeInTheDocument();

    // Fire the click event
    fireEvent.click(downloadButton);

    // Optionally check if the download functionality has been triggered
    // This would typically involve checking for a call to the download method, or checking for a URL creation
});
