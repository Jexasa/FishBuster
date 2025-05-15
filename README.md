
# FishBuster 

![image](https://github.com/user-attachments/assets/e6a3bf18-b8da-4ab6-9eb2-890a3b39ddd8)


Phishing Email Checker Extension
A Chrome extension to detect phishing emails in the top 5 webmail services (Gmail, Outlook, Yahoo Mail, AOL Mail, ProtonMail) using CheckPhish, VirusTotal, PhishTank APIs, and advanced heuristics. Free to use with a daily ad, ad-free for a one-time €0.99 payment. Supports donations through BuyMeACoffee (https://buymeacoffee.com/ksexasa).

## Features
- **Phishing Detection**: Combines APIs and heuristics (sender spoofing, urgency phrases, link patterns, SPF/DKIM checks).
- **Webmail Support**: Works with Gmail, Outlook, Yahoo Mail, AOL Mail, ProtonMail.
- **Security**: API key encryption, DOMPurify sanitization, CSP, GDPR/CCPA compliant.
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

## Compliance
- **GDPR/CCPA**: User consent for data sharing, anonymized data (hashed URLs, no PII).

## Contributing
Submit issues or PRs via GitHub. For feature requests, contact via BuyMeACoffee.

## License
MIT License
