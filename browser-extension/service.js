const API_BASE = 'http://localhost:5000/api';

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return await res.json();
  } catch (error) {
    throw new Error('Backend is offline');
  }
}

export async function analyzeUrl(url) {
    console.log("Sending request to backend...");

    const response = await fetch(`${API_BASE}/predict`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: url
        })
    });

    console.log("Response Status:", response.status);

    const data = await response.json();

    console.log("Prediction:", data);

    return data;
}
