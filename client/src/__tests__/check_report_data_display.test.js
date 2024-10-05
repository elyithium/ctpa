import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/extend-expect';
import Reports from '../pages/Reports'; // Adjust the import based on your structure

describe('Reports Component', () => {
  beforeEach(() => {
    // Mock localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: jest.fn(() => JSON.stringify({ report: { target: 'http://127.0.0.1:8080', createdAt: '2024-10-04' } })),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
      writable: true,
    });

    // Render the Reports component (make sure any necessary context providers are included)
    render(<Reports />);
  });

  test('displays report data correctly', () => {
    // Check if the report data is displayed correctly
    expect(screen.getByText(/Target:/i)).toBeInTheDocument();
    expect(screen.getByText(/http:\/\/example.com/i)).toBeInTheDocument();
    expect(screen.getByText(/Generated on:/i)).toBeInTheDocument();
    expect(screen.getByText(/2024-10-04/i)).toBeInTheDocument();
  });
});
