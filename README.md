// README.md
# Phishing Email Checker Extension

A Chrome extension to detect phishing emails in the top 5 webmail services (Gmail, Outlook, Yahoo Mail, AOL Mail, ProtonMail) using CheckPhish, VirusTotal, PhishTank APIs, and advanced heuristics. Free to use with a daily ad, ad-free for a one-time €0.99 payment. Supports donations via BuyMeACoffee and monetizes through anonymized phishing data sales.

## Features
- **Phishing Detection**: Combines APIs and heuristics (sender spoofing, urgency phrases, link patterns, SPF/DKIM checks).
- **Webmail Support**: Works with Gmail, Outlook, Yahoo Mail, AOL Mail, ProtonMail.
- **Monetization**:
  - Free with one ad per day (Google AdSense).
  - Ad-free for €0.99 (Stripe).
  - BuyMeACoffee donations.
  - Anonymized phishing data sales (opt-in, GDPR-compliant).
- **Security**: API key encryption, DOMPurify sanitization, CSP, GDPR/CCPA compliance.
- **Performance**: API caching, retry logic, optimized DOM queries.

## Installation
1. Clone or download this repository.
2. Create an `images` folder with `icon16.png`, `icon48.png`, `icon128.png` (from Flaticon with attribution).
3. Download `purify.min.js` from [DOMPurify](https://github.com/cure53/DOMPurify/releases) and place in `lib/domp purify.min.js`.
4. Load as an unpacked extension in Chrome/Edge (Developer Mode).

## Configuration
1. **API Keys**:
   - [CheckPhish](https://checkphish.ai/): Free, 250 scans/month.
   - [VirusTotal](https://www.virustotal.com/): Free, 5000 requests/day.
   - [PhishTank](https://phishtank.org/): Free, unlimited (throttled).
   - Enter keys in the options page (Extensions > Manage > Details > Extension options).
2. **Monetization**:
   - **Ads**: Sign up for Google AdSense, replace `ca-pub-YOUR_ADSENSE_CLIENT_ID` and `YOUR_AD_SLOT_ID` in `popup.html`.
   - **Ad-Free**: Set up Stripe Checkout for €0.99, replace `https://your-stripe-checkout-url.com` in `popup.js`.
   - **BuyMeACoffee**: Create account, update links in `popup.html` and `options.html`.
   - **Data Sales**: Set up Firebase backend, replace `https://your-backend.example.com/store-phishing-data` in `background.js`.
3. **Privacy Policy**: Host at `https://yourwebsite.example.com/privacy` (use Termly).

## Deployment
1. Test locally in Chrome/Edge.
2. Create a Chrome Web Store developer account ($99 one-time).
3. Zip the extension folder and upload to Chrome Web Store.
4. Promote on X with #Cybersecurity hashtags.

## Development
- **Scripts**:
  - `background.js`: API calls, ad logic, data storage.
  - `heuristics.js`: Client-side phishing detection (rewritten for error-free, robust analysis).
  - `content.js`: Email extraction and result display.
  - `popup.js`: UI and ad handling.
  - `options.js`: Settings management.
- **Dependencies**: DOMPurify (included).
- **Build**: No build step required; ensure `lib/domp purify.min.js` is included.

## Compliance
- **GDPR/CCPA**: User consent for data sharing, anonymized data (hashed URLs, no PII).
- **Chrome Web Store**: Permissions justified, CSP enforced, privacy policy linked.

## Contributing
Submit issues or PRs via GitHub. For feature requests, contact via BuyMeACoffee.

## License
MIT License. See LICENSE file (create one with `mit-license.org`).

## Support
- Email: your.email@example.com
- BuyMeACoffee: https://www.buymeacoffee.com/yourusername
```

```markdown