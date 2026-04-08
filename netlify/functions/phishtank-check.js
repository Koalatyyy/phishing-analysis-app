// netlify/functions/phishtank-check.js
// Proxy for PhishTank API to hide API key from client

export default async (req) => {
  if (req.method !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'POST only' })
    };
  }

  const { url } = JSON.parse(req.body);
  if (!url) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing url' })
    };
  }

  const apiKey = process.env.PHISHTANK_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'API key not configured' })
    };
  }

  try {
    const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        url,
        app_token: apiKey,
        format: 'json'
      })
    });

    const data = await response.json();
    return {
      statusCode: 200,
      body: JSON.stringify({
        url,
        inPhishTank: data.in_phishtank === 1,
        confidence: data.confidence || null,
        phishDetailURL: data.phish_detail_url || null
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};
