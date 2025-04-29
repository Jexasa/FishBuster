let isChecking = false;
let checkMessageListener = null;
let progressListener = null;

document.addEventListener('DOMContentLoaded', () => {
  console.log('[PhishingChecker] Popup DOMContentLoaded event fired');

  const checkButton = document.getElementById('checkButton');
  const cancelButton = document.getElementById('cancelButton');
  const statusDiv = document.getElementById('status');
  const progressBarContainer = document.getElementById('progressBarContainer');
  const progressBar = document.getElementById('progressBar');
  const logWindow = document.getElementById('logWindow');
  const resultsWindow = document.getElementById('resultsWindow');
  const resultsContent = document.getElementById('resultsContent');
  const closeResultsButton = document.getElementById('closeResults');
  const configButton = document.getElementById('configButton');

  if (!checkButton || !cancelButton || !statusDiv || !progressBarContainer || !progressBar || !logWindow || !resultsWindow || !resultsContent || !closeResultsButton || !configButton) {
    console.error('[PhishingChecker] One or more DOM elements are missing');
    return;
  }

  chrome.storage.local.set({ isChecking: false }, () => {
    console.log('[PhishingChecker] Reset isChecking flag on popup open');
  });

  checkButton.addEventListener('click', () => {
    if (!isChecking) {
      console.log('[PhishingChecker] Check button clicked, starting check');
      startCheckUI();
      chrome.storage.local.set({ isChecking: true });
      checkEmail();
    } else {
      console.log('[PhishingChecker] Check already in progress');
    }
  });

  cancelButton.addEventListener('click', () => {
    console.log('[PhishingChecker] Cancel button clicked');
    stopCheckUI();
    chrome.storage.local.set({ isChecking: false });
    chrome.runtime.sendMessage({ type: 'cancelCheck' });
  });

  closeResultsButton.addEventListener('click', () => {
    console.log('[PhishingChecker] Closing results window');
    resultsWindow.style.display = 'none';
  });

  configButton.addEventListener('click', () => {
    console.log('[PhishingChecker] Config button clicked');
    chrome.runtime.openOptionsPage();
  });

  window.addEventListener('unload', () => {
    console.log('[PhishingChecker] Popup unloading, resetting isChecking');
    chrome.storage.local.set({ isChecking: false });
    if (progressListener) chrome.runtime.onMessage.removeListener(progressListener);
    if (checkMessageListener) chrome.runtime.onMessage.removeListener(checkMessageListener);
  });

  console.log('[PhishingChecker] Popup initialized successfully');
});

function startCheckUI() {
  console.log('[PhishingChecker] Starting check UI');
  isChecking = true;
  document.getElementById('checkButton').style.display = 'none';
  document.getElementById('cancelButton').style.display = 'block';
  const progressBarContainer = document.getElementById('progressBarContainer');
  progressBarContainer.style.display = 'block';
  const logWindow = document.getElementById('logWindow');
  logWindow.style.display = 'block';
  logWindow.textContent = 'Starting email check...\n';
  document.getElementById('status').textContent = 'Checking email...';

  if (progressListener) {
    chrome.runtime.onMessage.removeListener(progressListener);
  }
  if (checkMessageListener) {
    chrome.runtime.onMessage.removeListener(checkMessageListener);
  }

  progressListener = (message, sender, sendResponse) => {
    console.log('[PhishingChecker] Popup received message:', message);
    if (message.type === 'progressUpdate') {
      console.log('[PhishingChecker] Progress update received:', message.phase, message.percentage);
      const logWindow = document.getElementById('logWindow');
      logWindow.textContent += `Phase: ${message.phase} (${message.percentage}%)\n`;
      logWindow.scrollTop = logWindow.scrollHeight;
      const progressBar = document.getElementById('progressBar');
      progressBar.style.width = `${message.percentage}%`;
      console.log('[PhishingChecker] Progress bar updated to:', progressBar.style.width);
    }
  };
  chrome.runtime.onMessage.addListener(progressListener);

  checkMessageListener = (message, sender, sendResponse) => {
    console.log('[PhishingChecker] Popup received message:', message);
    if (message.type === 'result') {
      console.log('[PhishingChecker] Analysis result received:', message.result);
      stopCheckUI();
      const resultsContent = document.getElementById('resultsContent');
      resultsContent.textContent = `Risk Level: ${message.result.riskLevel}\nScore: ${message.result.score}\n${message.result.warnings.length ? message.result.warnings.join('\n') : 'No warnings.'}`;
      const resultsWindow = document.getElementById('resultsWindow');
      resultsWindow.style.display = 'block';
      chrome.storage.local.set({ isChecking: false });
      console.log('[PhishingChecker] Results window displayed');
    } else if (message.type === 'error') {
      console.error('[PhishingChecker] Analysis error:', message.error);
      const logWindow = document.getElementById('logWindow');
      logWindow.textContent += `Error: Analysis failed - ${message.error}\n`;
      logWindow.scrollTop = logWindow.scrollHeight;
      stopCheckUI();
      const resultsContent = document.getElementById('resultsContent');
      resultsContent.textContent = `Error: Analysis failed - ${message.error}`;
      const resultsWindow = document.getElementById('resultsWindow');
      resultsWindow.style.display = 'block';
      chrome.storage.local.set({ isChecking: false });
      console.log('[PhishingChecker] Error displayed in results window');
    }
  };
  chrome.runtime.onMessage.addListener(checkMessageListener);
}

function stopCheckUI() {
  console.log('[PhishingChecker] Stopping check UI');
  isChecking = false;
  document.getElementById('checkButton').style.display = 'block';
  document.getElementById('cancelButton').style.display = 'none';
  document.getElementById('progressBarContainer').style.display = 'none';
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('logWindow').style.display = 'none';
  document.getElementById('status').textContent = 'Ready to check.';
}

function checkEmail() {
  console.log('[PhishingChecker] Initiating email check');
  const logWindow = document.getElementById('logWindow');

  logWindow.textContent += 'Querying active tab...\n';
  logWindow.scrollTop = logWindow.scrollHeight;

  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (!tabs || tabs.length === 0) {
      console.error('[PhishingChecker] No active tab found');
      logWindow.textContent += 'Error: No active tab found.\n';
      stopCheckUI();
      chrome.storage.local.set({ isChecking: false });
      return;
    }

    const tab = tabs[0];
    console.log('[PhishingChecker] Active tab found:', tab.id, tab.url);
    logWindow.textContent += `Active tab found: ${tab.url}\n`;
    logWindow.scrollTop = logWindow.scrollHeight;

    const supportedDomains = [
      'mail.google.com',
      'outlook.live.com',
      'mail.yahoo.com',
      'mail.aol.com',
      'mail.proton.me'
    ];
    const tabDomain = new URL(tab.url).hostname;
    if (!supportedDomains.some(domain => tabDomain.includes(domain))) {
      console.error('[PhishingChecker] Unsupported page:', tab.url);
      logWindow.textContent += `Error: Unsupported page (${tab.url}).\n`;
      stopCheckUI();
      chrome.storage.local.set({ isChecking: false });
      return;
    }

    logWindow.textContent += 'Sending checkEmail message to content script...\n';
    logWindow.scrollTop = logWindow.scrollHeight;

    const messageTimeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Message to content script timed out')), 5000);
    });

    Promise.race([
      new Promise((resolve, reject) => {
        chrome.tabs.sendMessage(tab.id, { type: 'checkEmail' }, response => {
          if (chrome.runtime.lastError) {
            console.error('[PhishingChecker] Failed to send message to content script:', chrome.runtime.lastError.message);
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          console.log('[PhishingChecker] Response from content script:', response);
          resolve(response);
        });
      }),
      messageTimeout
    ]).then(response => {
      console.log('[PhishingChecker] Message successfully sent to content script, response:', response);
      logWindow.textContent += 'Message sent to content script, waiting for analysis results...\n';
      logWindow.scrollTop = logWindow.scrollHeight;

      // Extend timeout for background script response
      const backgroundTimeout = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Background script did not respond in time')), 30000); // Increased to 30s
      });

      Promise.race([
        new Promise(resolve => {
          const listener = (message, sender, sendResponse) => {
            if (message.type === 'result' || message.type === 'error') {
              console.log('[PhishingChecker] Background response received, resolving timeout:', message);
              chrome.runtime.onMessage.removeListener(listener);
              resolve();
            }
          };
          chrome.runtime.onMessage.addListener(listener);
        }),
        backgroundTimeout
      ]).catch(error => {
        console.error('[PhishingChecker] Background response timeout:', error.message);
        logWindow.textContent += `Error: ${error.message}\n`;
        logWindow.scrollTop = logWindow.scrollHeight;
        stopCheckUI();
        const resultsContent = document.getElementById('resultsContent');
        resultsContent.textContent = `Error: ${error.message}`;
        const resultsWindow = document.getElementById('resultsWindow');
        resultsWindow.style.display = 'block';
        chrome.storage.local.set({ isChecking: false });
      });
    }).catch(error => {
      console.error('[PhishingChecker] Error sending message to content script:', error.message);
      logWindow.textContent += `Error: Failed to communicate with content script - ${error.message}\n`;
      logWindow.scrollTop = logWindow.scrollHeight;
      stopCheckUI();
      chrome.storage.local.set({ isChecking: false });
      const resultsContent = document.getElementById('resultsContent');
      resultsContent.textContent = `Error: ${error.message}`;
      const resultsWindow = document.getElementById('resultsWindow');
      resultsWindow.style.display = 'block';
    });
  });
}
