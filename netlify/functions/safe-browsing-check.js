// netlify/functions/safe-browsing-check.js
// Proxy for Google Safe Browsing API to hide API key from client

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

  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'API key not configured' })
    };
  }

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'phishing-analyzer', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );

    const data = await response.json();
    const matches = data.matches || [];
    const isMalicious = matches.length > 0;

    return {
      statusCode: 200,
      body: JSON.stringify({
        url,
        isMalicious,
        threats: matches.map(m => m.threatType)
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};
