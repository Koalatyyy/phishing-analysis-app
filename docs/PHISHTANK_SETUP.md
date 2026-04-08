# PhishTank Integration Setup

This guide walks through adding optional PhishTank URL checking to the analyzer.

## Overview

The analyzer now includes a checkbox to check URLs against the [PhishTank](https://www.phishtank.com/) database via a Netlify Function. The API key is stored securely on Netlify, never exposed in code.

## Prerequisites

- GitHub account (already have this)
- [Netlify](https://netlify.com) account (free)
- PhishTank API key (free, requires registration at https://www.phishtank.com/api_info.php)

## Step 1: Get a PhishTank API Key

1. Go to https://www.phishtank.com/api_info.php
2. Sign up and request an API key
3. You'll receive an email with your app token

## Step 2: Deploy to Netlify

### Option A: Using Netlify CLI (recommended)

```bash
npm install -g netlify-cli
cd c:\Users\Tom\source\repos\phishing-analysis-app
netlify deploy
```

Follow the prompts to:
- Connect your GitHub repo
- Set build command to: (leave blank)
- Set publish directory to: (leave blank, defaults to repo root)

### Option B: Using Netlify UI

1. Go to https://app.netlify.com
2. Click "New site from Git"
3. Connect your GitHub repo
4. Leave build settings blank (no build step needed)
5. Deploy

## Step 3: Set the API Key

### Via Netlify CLI:

```bash
netlify env:set PHISHTANK_API_KEY "your-api-key-here"
```

### Via Netlify UI:

1. Site Settings → Build & deploy → Environment
2. Click "Edit variables"
3. Add: `PHISHTANK_API_KEY` = `your-api-key-here`
4. Save and trigger a redeploy

## Step 4: Test Locally (Optional)

To test the function locally:

```bash
netlify functions:serve
# In another terminal:
curl -X POST http://localhost:9999/.netlify/functions/phishtank-check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'
```

## What's New

- **Checkbox in UI**: "Check URLs against PhishTank" (off by default)
- **Netlify Function**: `netlify/functions/phishtank-check.js` proxies requests
- **URL Results**: PhishTank hits appear as flags in the URL analysis section
- **Rate Limits**: PhishTank free tier = 5 requests/second, 500/day

## GitHub Activity

These commits establish the integration:

```bash
git add netlify/functions/phishtank-check.js netlify.toml index.html
git commit -m "Feat: add optional PhishTank URL checking via Netlify Functions"
git push
```

## Privacy

- Your API key is stored only on Netlify's servers
- Never stored in GitHub
- Email bodies are never sent to PhishTank (only extracted URLs)
- All header analysis still runs locally in the browser

## Troubleshooting

**"Check PhishTank" button disabled after analysis?**
- Network error or Netlify function timeout. Check browser console for errors.

**PhishTank results not showing?**
- Confirm `PHISHTANK_API_KEY` is set in Netlify environment variables
- Check that the function deployed successfully: `netlify functions:list`

**Rate limit hit?**
- PhishTank free tier: 500 requests/day. Consider caching results if needed.
