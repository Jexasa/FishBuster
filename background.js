const RATE_LIMITS = {
  checkPhish: { max: 8, per: 3600 * 1000 },
  virusTotal: { max: 4, per: 60 * 1000 },
  phishTank: { max: 60, per: 3600 * 1000 }
};

const requestCounts = {
  checkPhish: { count: 0, resetTime: 0 },
  virusTotal: { count: 0, resetTime: 0 },
  phishTank: { count: 0, resetTime: 0 }
};

const API_CACHE_KEY = 'apiCache';
const CACHE_DURATION = 24 * 60 * 60 * 1000;
const API_TIMEOUT = 10000;

let isCheckCancelled = false;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (message.type === 'analyzeEmail') {
      isCheckCancelled = false;
      analyzeEmail(message.emailData).then(analysis => {
        if (!isCheckCancelled) {
          sendResponse({ result: analysis });
          if (analysis.riskLevel === 'High' || analysis.riskLevel === 'Medium') {
            storePhishingData(message.emailData, analysis).catch(err => logError('Data storage failed', err));
          }
        }
      }).catch(err => {
        if (!isCheckCancelled) {
          logError('Analysis failed', err);
          sendResponse({ result: { riskLevel: 'Error', score: 0, warnings: ['Analysis failed: ' + err.message] } });
        }
      });
    } else if (message.type === 'getApiKeys') {
      chrome.storage.sync.get(['checkPhishKey', 'virusTotalKey', 'phishTankKey'], keys => {
        sendResponse({
          checkPhishKey: decryptKey(keys.checkPhishKey),
          virusTotalKey: decryptKey(keys.virusTotalKey),
          phishTankKey: decryptKey(keys.phishTankKey)
        });
      });
    } else if (message.type === 'cancelCheck') {
      isCheckCancelled = true;
      sendResponse({ success: true });
    } else if (message.type === 'initiatePayment') {
      initiateStripePayment().then(checkoutUrl => {
        sendResponse({ checkoutUrl });
      }).catch(err => {
        logError('Payment initiation failed', err);
        sendResponse({ error: 'Failed to initiate payment' });
      });
    } else if (message.type === 'reopenPopup') {
      chrome.action.openPopup();
    }
  } catch (err) {
    logError('Message handling failed', err);
    sendResponse({ error: 'Internal error: ' + err.message });
  }
  return true;
});

function logError(message, error) {
  console.error(`[PhishingChecker] ${message}:`, error);
}

async function analyzeEmail(emailData) {
  let score = 0;
  let warnings = [];

  const sender = DOMPurify.sanitize(emailData.sender.toLowerCase());
  const content = DOMPurify.sanitize(emailData.content.toLowerCase());
  const links = emailData.links.map(link => DOMPurify.sanitize(link)).filter(link => isValidUrl(link));

  const heuristicResult = await window.checkPhishingHeuristics(sender, content, links, emailData.domain);
  score += heuristicResult.score;
  warnings.push(...heuristicResult.warnings);

  const keys = await new Promise(resolve => chrome.storage.sync.get(['checkPhishKey', 'virusTotalKey', 'phishTankKey'], resolve));
  const checkPhishKey = decryptKey(keys.checkPhishKey);
  const virusTotalKey = decryptKey(keys.virusTotalKey);
  const phishTankKey = decryptKey(keys.phishTankKey);

  if (checkPhishKey || virusTotalKey || phishTankKey) {
    const apiResults = await Promise.all([
      checkPhishKey ? checkCachedApi('checkPhish', links, checkPhishingApi) : Promise.resolve({ isMalicious: false, reason: 'CheckPhish API key not configured' }),
      virusTotalKey ? checkCachedApi('virusTotal', links, checkVirusTotalApi) : Promise.resolve({ isMalicious: false, reason: 'VirusTotal API key not configured' }),
      phishTankKey ? checkCachedApi('phishTank', links, checkPhishTankApi) : Promise.resolve({ isMalicious: false, reason: 'PhishTank API key not configured' })
    ]);

    for (const result of apiResults) {
      if (result.isMalicious) {
        score += 20;
        warnings.push(result.reason);
      }
    }

    if (apiResults.every(r => !r.isMalicious && r.reason.includes('unavailable'))) {
      score += 10;
      warnings.push('All configured APIs unavailable; relying on heuristics.');
    }
  } else {
    warnings.push('No API keys configured; analysis based on heuristics only.');
  }

  let riskLevel = 'Low';
  if (score > 70) riskLevel = 'High';
  else if (score > 40) riskLevel = 'Medium';

  return { riskLevel, score: Math.min(score, 100), warnings };
}

function isValidUrl(url) {
  try {
    new URL(url);
    return url.startsWith('https://') || url.startsWith('http://');
  } catch {
    return false;
  }
}

async function canMakeRequest(api) {
  const now = Date.now();
  const limit = RATE_LIMITS[api];
  const count = requestCounts[api];

  if (now > count.resetTime) {
    count.count = 0;
    count.resetTime = now + limit.per;
  }

  if (count.count >= limit.max) return false;
  count.count++;
  return true;
}

async function checkCachedApi(apiName, links, apiFunction) {
  const cacheKey = `${apiName}:${links.join('|')}`;
  const cached = await getCachedResult(cacheKey);
  if (cached) return cached;

  const result = await Promise.race([
    apiFunction(links),
    new Promise((_, reject) => setTimeout(() => reject(new Error('API timeout')), API_TIMEOUT))
  ]);
  await cacheResult(cacheKey, result);
  return result;
}

async function getCachedResult(key) {
  const cache = await new Promise(resolve => chrome.storage.local.get([API_CACHE_KEY], resolve));
  const cachedData = cache[API_CACHE_KEY] || {};
  if (cachedData[key] && Date.now() - cachedData[key].timestamp < CACHE_DURATION) {
    return cachedData[key].result;
  }
  return null;
}

async function cacheResult(key, result) {
  const cache = await new Promise(resolve => chrome.storage.local.get([API_CACHE_KEY], resolve));
  const cachedData = cache[API_CACHE_KEY] || {};
  cachedData[key] = { result, timestamp: Date.now() };
  chrome.storage.local.set({ [API_CACHE_KEY]: cachedData });
}

async function checkPhishingApi(links) {
  try {
    if (!(await canMakeRequest('checkPhish'))) {
      return { isMalicious: false, reason: 'CheckPhish rate limit reached' };
    }
    const keys = await new Promise(resolve => chrome.storage.sync.get(['checkPhishKey'], resolve));
    const apiKey = decryptKey(keys.checkPhishKey);
    if (!apiKey) return { isMalicious: false, reason: 'CheckPhish API key not configured' };

    let isMalicious = false;
    let reason = 'No malicious links found';
    for (const url of links) {
      const scanResponse = await fetch('https://developers.checkphish.ai/api/neo/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey, urlInfo: { url } })
      });
      if (!scanResponse.ok) throw new Error('CheckPhish scan failed');
      const scanData = await scanResponse.json();
      const jobID = scanData.jobID;
      let attempts = 0;
      while (attempts < 5 && !isCheckCancelled) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const statusResponse = await fetch('https://developers.checkphish.ai/api/neo/scan/status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apiKey, jobID })
        });
        if (!statusResponse.ok) throw new Error('CheckPhish status check failed');
        const statusData = await statusResponse.json();
        if (statusData.status === 'DONE') {
          if (statusData.insights && statusData.insights.disposition === 'malicious') {
            isMalicious = true;
            reason = `Malicious URL detected: ${url}`;
            break;
          }
          break;
        }
        attempts++;
      }
      if (isMalicious) break;
    }
    return { isMalicious, reason };
  } catch (error) {
    logError('CheckPhish API check failed', error);
    return { isMalicious: false, reason: 'CheckPhish API unavailable: ' + error.message };
  }
}

async function checkVirusTotalApi(links) {
  try {
    if (!(await canMakeRequest('virusTotal'))) {
      return { isMalicious: false, reason: 'VirusTotal rate limit reached' };
    }
    const keys = await new Promise(resolve => chrome.storage.sync.get(['virusTotalKey'], resolve));
    const apiKey = decryptKey(keys.virusTotalKey);
    if (!apiKey) return { isMalicious: false, reason: 'VirusTotal API key not configured' };

    let isMalicious = false;
    let reason = 'No malicious links found';
    for (const url of links) {
      const encodedUrl = btoa(url);
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
        method: 'GET',
        headers: { 'x-apikey': apiKey }
      });
      if (!response.ok) throw new Error('VirusTotal request failed');
      const data = await response.json();
      if (data.data && data.data.attributes && data.data.attributes.last_analysis_stats) {
        const stats = data.data.attributes.last_analysis_stats;
        if (stats.malicious > 0 || stats.suspicious > 0) {
          isMalicious = true;
          reason = `Malicious URL detected by VirusTotal: ${url} (${stats.malicious} engines flagged)`;
          break;
        }
      }
    }
    return { isMalicious, reason };
  } catch (error) {
    logError('VirusTotal API check failed', error);
    return { isMalicious: false, reason: 'VirusTotal API unavailable: ' + error.message };
  }
}

async function checkPhishTankApi(links) {
  try {
    if (!(await canMakeRequest('phishTank'))) {
      return { isMalicious: false, reason: 'PhishTank rate limit reached' };
    }
    const keys = await new Promise(resolve => chrome.storage.sync.get(['phishTankKey'], resolve));
    const apiKey = decryptKey(keys.phishTankKey);
    if (!apiKey) return { isMalicious: false, reason: 'PhishTank API key not configured' };

    let isMalicious = false;
    let reason = 'No malicious links found';
    for (const url of links) {
      const formData = new FormData();
      formData.append('url', encodeURIComponent(url));
      formData.append('app_key', apiKey);
      formData.append('format', 'json');
      const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
        method: 'POST',
        body: formData
      });
      if (!response.ok) throw new Error('PhishTank request failed');
      const data = await response.json();
      if (data.results && data.results.in_database && data.results.valid) {
        isMalicious = true;
        reason = `PhishTank confirmed phishing URL: ${url}`;
        break;
      }
    }
    return { isMalicious, reason };
  } catch (error) {
    logError('PhishTank API check failed', error);
    return { isMalicious: false, reason: 'PhishTank API unavailable: ' + error.message };
  }
}

async function storePhishingData(emailData, analysis) {
  const { dataSharingConsent } = await new Promise(resolve => 
    chrome.storage.sync.get(['dataSharingConsent'], resolve)
  );
  if (!dataSharingConsent) return;

  const anonymizedData = {
    urls: emailData.links.map(url => hashUrl(url)),
    senderDomain: emailData.sender.split('@')[1] || 'unknown',
    keywords: analysis.warnings.filter(w => w.includes('keyword')).map(w => w.match(/"([^"]+)"/)?.[1]).filter(Boolean),
    riskLevel: analysis.riskLevel,
    timestamp: Date.now()
  };

  // Skip external data storage since there's no backend
  console.log('[PhishingChecker] Anonymized data (not stored due to no backend):', anonymizedData);
}

function hashUrl(url) {
  let hash = 0;
  for (let i = 0; i < url.length; i++) {
    hash = ((hash << 5) - hash) + url.charCodeAt(i);
    hash |= 0;
  }
  return hash.toString();
}

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

async function initiateStripePayment() {
  const user = firebase.auth().currentUser;
  if (!user) {
    // Fallback to anonymous user ID if Firebase Auth fails
    const userId = 'anonymous-' + Date.now();
    chrome.storage.local.set({ tempUserId: userId });
  }

  const checkoutSession = await firebase.firestore().collection('users').doc(user ? user.uid : 'anonymous-' + Date.now()).collection('checkout_sessions').add({
    price: 'price_1YOUR_STRIPE_PRICE_ID',
    success_url: chrome.runtime.getURL('success.html') + '?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: chrome.runtime.getURL('popup.html')
  });

  return new Promise((resolve, reject) => {
    checkoutSession.onSnapshot(snap => {
      const { url } = snap.data();
      if (url) {
        resolve(url);
      }
    }, err => reject(err));
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['version'], data => {
    if (data.version !== chrome.runtime.getManifest().version) {
      chrome.storage.local.set({ version: chrome.runtime.getManifest().version });
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/icon128.png',
        title: 'Phishing Checker Updated',
        message: 'New features and improvements! Check the options page for details.'
      });
    }
  });
});