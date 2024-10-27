import axios from 'axios';

const instance = axios.create({
	baseURL: process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000', // This should match the Flask server URL
	headers: {
		'Content-Type': 'application/json',
	},
	timeout: 10000, // 10 seconds timeout
});

// Request Interceptor
instance.interceptors.request.use(
  config => {
    // Modify the request config if needed (e.g., add auth token)
    // const token = localStorage.getItem('authToken');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// Response Interceptor
instance.interceptors.response.use(
  response => {
    // Handle the response data here if needed
    return response;
  },
  error => {
    // Handle errors globally
    console.error('API Error:', error);
    if (error.response) {
      console.error('Data:', error.response.data);
      console.error('Status:', error.response.status);
      console.error('Headers:', error.response.headers);
    } else if (error.request) {
      console.error('Request:', error.request);
    } else {
      console.error('Message:', error.message);
    }
    return Promise.reject(error);
  }
);

export default instance;
