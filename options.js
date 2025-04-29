document.addEventListener('DOMContentLoaded', () => {
  try {
    // Load existing settings
    chrome.storage.sync.get(['checkPhishKey', 'virusTotalKey', 'phishTankKey', 'dataSharingConsent'], data => {
      document.getElementById('checkPhishKey').value = decryptKey(data.checkPhishKey) || '';
      document.getElementById('virusTotalKey').value = decryptKey(data.virusTotalKey) || '';
      document.getElementById('phishTankKey').value = decryptKey(data.phishTankKey) || '';
      document.getElementById('dataSharingConsent').value = data.dataSharingConsent ? 'true' : 'false';
    });

    // Save button handler
    document.getElementById('saveButton').addEventListener('click', () => {
      const checkPhishKey = document.getElementById('checkPhishKey').value.trim();
      const virusTotalKey = document.getElementById('virusTotalKey').value.trim();
      const phishTankKey = document.getElementById('phishTankKey').value.trim();
      const dataSharingConsent = document.getElementById('dataSharingConsent').value === 'true';

      chrome.storage.sync.set({
        checkPhishKey: encryptKey(checkPhishKey),
        virusTotalKey: encryptKey(virusTotalKey),
        phishTankKey: encryptKey(phishTankKey),
        dataSharingConsent
      }, () => {
        const status = document.getElementById('status');
        status.textContent = 'Settings saved successfully!';
        setTimeout(() => { status.textContent = ''; }, 3000);
      });
    });

    // Back button handler
    document.getElementById('backButton').addEventListener('click', () => {
      // Notify the popup to reopen
      chrome.runtime.sendMessage({ type: 'reopenPopup' }, () => {
        // Attempt to close the options page
        window.close();
      });
    });
  } catch (err) {
    console.error('[PhishingChecker] Options initialization error:', err);
    document.getElementById('status').textContent = 'Error loading settings.';
  }
});

// Add message listener in background.js to handle reopenPopup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'reopenPopup') {
    chrome.action.openPopup();
  }
});

// Reuse encryptKey and decryptKey from background.js (assumed to be global or copied)
function encryptKey(key) {
  if (!key) return '';
  const secret = 'phishing-checker-secret';
  let result = '';
  for (let i = 0; i < key.length; i++) {
    result += String.fromCharCode(key.charCodeAt(i) ^ secret.charCodeAt(i % secret.length));
  }
  return btoa(result);
}

function decryptKey(encrypted) {
  if (!encrypted) return '';
  try {
    const secret = 'phishing-checker-secret';
    const decoded = atob(encrypted);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      result += String.fromCharCode(decoded.charCodeAt(i) ^ secret.charCodeAt(i % secret.length));
    }
    return result;
  } catch {
    return '';
  }
}