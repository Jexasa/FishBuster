// README.md
# Phishing Email Checker Extension

A Chrome extension to detect phishing emails in the top 5 webmail services (Gmail, Outlook, Yahoo Mail, AOL Mail, ProtonMail) using CheckPhish, VirusTotal, PhishTank APIs, and advanced heuristics. Free to use with a daily ad, ad-free for a one-time €0.99 payment. Supports donations through BuyMeACoffee.

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

## Configure API Keys:
   - [CheckPhish](https://checkphish.ai/): Free, 250 scans/month.
   - [VirusTotal](https://www.virustotal.com/): Free, 5000 requests/day.
   - [PhishTank](https://phishtank.org/): Free, unlimited (throttled).
   - Enter keys in the options page (Extensions > Manage > Details > Extension options).

## Development
- **Scripts**:
  - `background.js`: API calls, ad logic, data storage.
  - `heuristics.js`: Client-side phishing detection (rewritten for error-free, robust analysis).
  - `content.js`: Email extraction and result display.
  - `popup.js`: UI and ad handling.
  - `options.js`: Settings management.
- **Dependencies**: DOMPurify (included).
- 
## Compliance
- **GDPR/CCPA**: User consent for data sharing, anonymized data (hashed URLs, no PII).

## Contributing
Submit issues or PRs via GitHub. For feature requests, contact via BuyMeACoffee.

## License
MIT License. See LICENSE file .

## Support
- Email: m.a.kitsios@gmail.com
- BuyMeACoffee: https://www.buymeacoffee.com/Jexasa
```

```markdown
