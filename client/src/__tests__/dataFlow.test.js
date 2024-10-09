import { render, screen, fireEvent } from '@testing-library/react';
import App from '../App'; // Adjust path as necessary

test('Validate Data Flow from Frontend Input to Backend Processing', async () => {
    render(<App />);
    fireEvent.change(screen.getByPlaceholderText(/enter url/i), {
        target: { value: 'http://127.0.0.1:8080' },
    });
    fireEvent.change(screen.getByLabelText(/scanner type/i), {
        target: { value: 'Full Scan' },
    });
    fireEvent.click(screen.getByText(/start scan/i));

    const reportData = await screen.findByText(/report/i); // Adjust based on expected report content
    expect(reportData).toBeInTheDocument();
});
