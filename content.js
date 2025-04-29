chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'checkEmail') {
    try {
      chrome.runtime.sendMessage({ type: 'checkAdStatus' }, response => {
        if (!response.canProceed) {
          displayResult({
            riskLevel: 'Locked',
            score: 0,
            warnings: ['Please watch an ad or purchase ad-free access.']
          });
          return;
        }
        const emailData = extractEmailData();
        if (emailData) {
          chrome.runtime.sendMessage({
            type: 'analyzeEmail',
            emailData
          }, response => {
            displayResult(response.result);
          });
        } else {
          displayResult({
            riskLevel: 'Unknown',
            score: 0,
            warnings: ['Unable to extract email data. Ensure you are viewing an email.']
          });
          console.warn('[PhishingChecker] Email extraction failed: No email content or sender found.');
        }
      });
    } catch (err) {
      console.error('[PhishingChecker] Content script error:', err);
      displayResult({
        riskLevel: 'Error',
        score: 0,
        warnings: ['Content extraction failed. Check console for details.']
      });
    }
  }
});

function extractEmailData() {
  try {
    let emailContainer, senderElement, links;
    const hostname = window.location.hostname;
    const selectors = {
      'mail.google.com': {
        content: '.a3s.aXjCH, .ii.gt',
        sender: '.gD',
        header: '.ha, .gs'
      },
      'outlook.live.com': {
        content: '.elementContainer div[role="document"]',
        sender: 'span[automatiod="emailAddress"]',
        header: '.headerContainer'
      },
      'mail.yahoo.com': {
        content: '.msg-body',
        sender: '.msg-header-from',
        header: '.msg-header'
      },
      'mail.aol.com': {
        content: '.msgBody',
        sender: '.from-address',
        header: '.messageHeader'
      },
      'mail.proton.me': {
        content: '.message-content',
        sender: '.message-header-from',
        header: '.message-header'
      }
    };

    const config = Object.keys(selectors).find(key => hostname.includes(key));
    if (!config) {
      console.warn('[PhishingChecker] Unsupported email service:', hostname);
      return null;
    }

    emailContainer = document.querySelector(selectors[config].content);
    senderElement = document.querySelector(selectors[config].sender);
    links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(href => href.startsWith('http'));

    if (!emailContainer) {
      console.warn('[PhishingChecker] Email content not found using selector:', selectors[config].content);
      return null;
    }
    if (!senderElement) {
      console.warn('[PhishingChecker] Sender element not found using selector:', selectors[config].sender);
      return null;
    }

    const emailData = {
      sender: senderElement.getAttribute('email') || senderElement.textContent || '',
      content: emailContainer.textContent || '',
      links,
      domain: hostname
    };

    if (!emailData.sender || !emailData.content) {
      console.warn('[PhishingChecker] Incomplete email data:', emailData);
      return null;
    }

    return emailData;
  } catch (error) {
    console.error('[PhishingChecker] Extraction error:', error);
    return null;
  }
}

function displayResult(result) {
  try {
    let backgroundColor;
    switch (result.riskLevel) {
      case 'High': backgroundColor = '#ffcccc'; break;
      case 'Medium': backgroundColor = '#fff4cc'; break;
      case 'Low': backgroundColor = '#ccffcc'; break;
      default: backgroundColor = '#f0f0f0';
    }

    const banner = document.createElement('div');
    banner.className = 'phishing-check-banner';
    banner.style.backgroundColor = backgroundColor;
    banner.innerHTML = DOMPurify.sanitize(`
      <strong>Phishing Risk: ${result.riskLevel}</strong> (Score: ${result.score})<br>
      ${result.warnings.length ? '<ul>' + result.warnings.map(w => `<li>${w}</li>`).join('') + '</ul>' : 'No specific warnings.'}
    `);

    const hostname = window.location.hostname;
    const headerSelector = Object.keys({
      'mail.google.com': '.ha, .gs',
      'outlook.live.com': '.headerContainer',
      'mail.yahoo.com': '.msg-header',
      'mail.aol.com': '.messageHeader',
      'mail.proton.me': '.message-header'
    }).find(key => hostname.includes(key));

    const header = headerSelector ? document.querySelector(headerSelector) : null;
    if (header) {
      header.prepend(banner);
    } else {
      document.body.prepend(banner);
      console.warn('[PhishingChecker] Header not found, banner appended to body');
    }
  } catch (err) {
    console.error('[PhishingChecker] Display result error:', err);
  }
}