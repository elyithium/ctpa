import { render, screen, fireEvent } from '@testing-library/react';
import App from '../App'; // Adjust path as necessary

test('Check User Navigation after Scan Completion', async () => {
    render(<App />);
    fireEvent.click(screen.getByText(/start scan/i)); // Trigger scan

    // Wait for navigation
    await waitFor(() => expect(screen.getByText(/reports/i)).toBeInTheDocument());
});
