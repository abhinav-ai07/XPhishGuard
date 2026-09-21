import axios from 'axios';

// Connect to Flask backend (configurable via VITE_API_URL)
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000, // 15 second timeout for scanning
});

export const scanUrl = async (url) => {
  try {
    const response = await apiClient.post('/predict', { url });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data.message || 'Server responded with an error');
    } else if (error.request) {
      throw new Error('No response from backend. Ensure Flask is running.');
    } else {
      throw new Error('Error setting up the request.');
    }
  }
};
