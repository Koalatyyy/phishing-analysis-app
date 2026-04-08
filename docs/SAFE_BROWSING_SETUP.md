# Google Safe Browsing Integration Setup

This guide walks through adding optional URL safety checking via Google Safe Browsing API.

## Overview

The analyzer now includes a checkbox to check URLs against [Google Safe Browsing](https://safebrowsing.google.com/), which detects malware, phishing, and unwanted software. The API key is stored securely on Netlify, never exposed in code.

## Prerequisites

- GitHub account (already have this)
- [Netlify](https://netlify.com) account (free)
- Google Cloud project with Safe Browsing API enabled (free tier: 5M requests/month)

## Step 1: Get a Google Safe Browsing API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Search for "Safe Browsing API"
4. Click "Enable" (free tier available)
5. Go to "Credentials" → "Create Credentials" → "API Key"
6. Copy your API key

## Step 2: Deploy to Netlify

### Option A: Using Netlify CLI (recommended)

```bash
npm install -g netlify-cli
cd c:\Users\Tom\source\repos\phishing-analysis-app
netlify deploy
```

Follow the prompts to connect your GitHub repo and deploy.

### Option B: Using Netlify UI

1. Go to https://app.netlify.com
2. Click "New site from Git"
3. Connect your GitHub repo
4. Leave build settings blank (no build step needed)
5. Deploy

## Step 3: Set the API Key

### Via Netlify CLI:

```bash
netlify env:set GOOGLE_SAFE_BROWSING_API_KEY "your-api-key-here"
```

### Via Netlify UI:

1. Site Settings → Build & deploy → Environment
2. Click "Edit variables"
3. Add: `GOOGLE_SAFE_BROWSING_API_KEY` = `your-api-key-here`
4. Save and trigger a redeploy

## Step 4: Test Locally (Optional)

```bash
netlify functions:serve
# In another terminal:
curl -X POST http://localhost:9999/.netlify/functions/safe-browsing-check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://malware.example.com"}'
```

## What's New

- **Checkbox in UI**: "Check URLs against Safe Browsing" (off by default)
- **Netlify Function**: `netlify/functions/safe-browsing-check.js` proxies requests
- **URL Results**: Known malicious URLs appear as flags in the URL analysis section
- **Rate Limits**: Free tier = 5M requests/month (plenty for personal use)

## GitHub Activity

These commits establish the integration:

```bash
git add netlify/functions/safe-browsing-check.js netlify.toml index.html
git commit -m "Feat: add optional URL checking via Google Safe Browsing API"
git push
```

## Privacy

- Your API key is stored only on Netlify's servers
- Never stored in GitHub
- Email bodies are never sent to Google (only extracted URLs)
- All header analysis still runs locally in the browser

## What Safe Browsing Detects

- **Phishing sites** — credential theft, impersonation
- **Malware** — drive-by downloads, exploits
- **Unwanted software** — adware, PUPs, trojans

Note: Safe Browsing is URL-based. Spam emails with legitimate infrastructure won't be flagged.

## Troubleshooting

**"Check Safe Browsing" button disabled after analysis?**
- Network error or Netlify function timeout. Check browser console for errors.

**Safe Browsing results not showing?**
- Confirm `GOOGLE_SAFE_BROWSING_API_KEY` is set in Netlify environment variables
- Check that the function deployed successfully: `netlify functions:list`

**"API key not configured" error?**
- Make sure you set the environment variable *after* deploying the function
- Redeploy to apply environment changes: `netlify deploy --prod`

## Alternatives

If you prefer a different service:
- **URLhaus API** — Free, no registration, malware URLs only
- **VirusTotal API** — Multi-engine scanning, free tier available
