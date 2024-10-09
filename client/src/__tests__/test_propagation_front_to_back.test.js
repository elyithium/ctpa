import { render, screen, fireEvent } from '@testing-library/react';
import App from '../App'; // Adjust the path according to your structure
import axios from 'axios';

jest.mock('axios');

test('displays error message for invalid URL', async () => {
  axios.post.mockRejectedValueOnce({ response: { status: 400, data: { message: "Invalid URL" } } });

  render(<App />); // Render your main component

  fireEvent.change(screen.getByPlaceholderText(/enter url/i), {
    target: { value: 'invalid-url' },
  });

  fireEvent.click(screen.getByText(/start scan/i)); // Click the button to start the scan

  const errorMessage = await screen.findByText(/invalid url/i); // Adjust to the expected error message
  expect(errorMessage).toBeInTheDocument(); // Assert that the error message is displayed
});
