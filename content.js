console.log('[PhishingChecker] Content script loaded on page:', window.location.href);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'checkEmail') {
    console.log('[PhishingChecker] Received checkEmail message in content script');
    try {
      const emailData = extractEmailData();
      console.log('[PhishingChecker] Email data extracted:', emailData);
      chrome.runtime.sendMessage({ type: 'analyzeEmail', emailData }, response => {
        console.log('[PhishingChecker] AnalyzeEmail message sent, response:', response);
      });
      console.log('[PhishingChecker] Sent analyzeEmail message to background script');
      sendResponse({ success: true });
    } catch (err) {
      console.error('[PhishingChecker] Error in content script:', err.message, err.stack);
      chrome.runtime.sendMessage({ error: 'Content script error: ' + err.message });
      sendResponse({ error: err.message });
    }
    return true;
  }
});

function extractEmailData() {
  console.log('[PhishingChecker] Extracting email data');
  let sender = 'unknown.sender@domain.com';
  let content = 'Unable to extract email content';
  let links = [];

  if (window.location.hostname.includes('mail.google.com')) {
    const emailContainer = document.querySelector('.a3s.aiN') || document.querySelector('.ii.gt');
    if (emailContainer) {
      content = emailContainer.textContent.trim();
    }

    const senderElement = document.querySelector('span[email]');
    if (senderElement) {
      sender = senderElement.getAttribute('email');
    }

    const linkElements = document.querySelectorAll('a[href]');
    links = Array.from(linkElements)
      .map(link => link.href)
      .filter(href => href.startsWith('http') || href.startsWith('https'));
  } else {
    throw new Error('Unsupported email provider');
  }

  if (!sender || !content) {
    throw new Error('Failed to extract email data');
  }

  const domain = sender.split('@')[1] || 'unknown';
  return { sender, content, links, domain };
}
