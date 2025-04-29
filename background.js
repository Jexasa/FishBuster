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
const CHECK_TIMEOUT = 30000;
const MAX_LINKS_TO_PROCESS = 5;

let isCheckCancelled = false;

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>&"']/g, match => ({
    '<': '<',
    '>': '>',
    '&': '&',
    '"': '"',
    "'": '''
  }[match]));
}

function checkPhishingHeuristics(sender, content, links, domain) {
  console.log('[PhishingChecker] Running heuristic analysis for domain:', domain);
  let score = 0;
  const warnings = [];

  const trustedDomains = [
    'e-food.gr',
    'gmail.com',
    'outlook.com',
    'yahoo.com'
  ];
  if (trustedDomains.includes(domain)) {
    console.log('[PhishingChecker] Trusted domain detected, reducing suspicion:', domain);
    return { score: 0, warnings: ['Trusted domain, no further checks applied.'] };
  }

  const suspiciousSenderPatterns = [
    /noreply@.*\.xyz/i,
    /support@.*\.top/i,
    /.*@.*\.ru/i
  ];
  if (suspiciousSenderPatterns.some(pattern => pattern.test(sender))) {
    score += 20;
    warnings.push('Suspicious sender domain detected');
  }

  const suspiciousKeywords = [
    'urgent',
    'verify your account',
    'password reset',
    'click here immediately'
  ];
  suspiciousKeywords.forEach(keyword => {
    if (content.includes(keyword)) {
      score += 10;
      warnings.push(`Suspicious keyword detected: "${keyword}"`);
    }
  });

  if (content.includes('unsubscribe')) {
    const hasOtherSuspiciousKeywords = suspiciousKeywords.some(keyword => content.includes(keyword));
    if (hasOtherSuspiciousKeywords) {
      score += 10;
      warnings.push('Suspicious keyword detected: "unsubscribe" with other risky keywords');
    } else {
      const footerPatterns = [
        /unsubscribe\s*\|/,
        /to\s*unsubscribe\s*click/,
        /unsubscribe\s*from\s*this\s*email/
      ];
      if (footerPatterns.some(pattern => pattern.test(content))) {
        warnings.push('Unsubscribe detected in footer, likely benign');
      } else {
        score += 5;
        warnings.push('Suspicious keyword detected: "unsubscribe" (not in footer)');
      }
    }
  }

  const suspiciousLinkDomains = [
    '.xyz',
    '.top',
    '.ru'
  ];
  links.forEach(link => {
    try {
      const url = new URL(link);
      if (suspiciousLinkDomains.some(suffix => url.hostname.endsWith(suffix))) {
        score += 15;
        warnings.push(`Suspicious link domain detected: ${url.hostname}`);
      }
    } catch (e) {
      warnings.push(`Invalid URL detected: ${link}`);
    }
  });

  return { score, warnings };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[PhishingChecker] Message received in background script:', message);
  try {
    if (message.type === 'analyzeEmail') {
      console.log('[PhishingChecker] Processing analyzeEmail message:', message);
      isCheckCancelled = false;
      Promise.race([
        analyzeEmail(message.emailData),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Analysis timed out')), CHECK_TIMEOUT))
      ]).then(analysis => {
        if (!isCheckCancelled) {
          console.log('[PhishingChecker] Analysis completed, sending result:', analysis);
          chrome.runtime.sendMessage({ type: 'result', result: analysis }, () => {
            console.log('[PhishingChecker] Result message sent to popup');
            if (chrome.runtime.lastError) {
              console.error('[PhishingChecker] Error sending result to popup:', chrome.runtime.lastError.message);
            }
          });
          if (analysis.riskLevel === 'High' || analysis.riskLevel === 'Medium') {
            storePhishingData(message.emailData, analysis).catch(err => logError('Data storage failed', err));
          }
        } else {
          console.log('[PhishingChecker] Check was cancelled, not sending result');
        }
        sendResponse({ success: true });
      }).catch(err => {
        if (!isCheckCancelled) {
          logError('Analysis failed', err);
          chrome.runtime.sendMessage({ type: 'error', error: err.message }, () => {
            console.log('[PhishingChecker] Error message sent to popup');
            if (chrome.runtime.lastError) {
              console.error('[PhishingChecker] Error sending error message to popup:', chrome.runtime.lastError.message);
            }
          });
        }
        sendResponse({ error: err.message });
      });
    } else if (message.type === 'getApiKeys') {
      console.log('[PhishingChecker] Retrieving API keys');
      chrome.storage.sync.get(['checkPhishKey', 'virusTotalKey', 'phishTankKey'], keys => {
        sendResponse({
          checkPhishKey: decryptKey(keys.checkPhishKey),
          virusTotalKey: decryptKey(keys.virusTotalKey),
          phishTankKey: decryptKey(keys.phishTankKey)
        });
      });
    } else if (message.type === 'cancelCheck') {
      console.log('[PhishingChecker] Cancelling check');
      isCheckCancelled = true;
      sendResponse({ success: true });
    } else if (message.type === 'reopenPopup') {
      chrome.action.openPopup();
    } else if (message.type === 'progressUpdate') {
      chrome.runtime.sendMessage(message, () => {
        console.log('[PhishingChecker] Progress update forwarded to popup');
        if (chrome.runtime.lastError) {
          console.error('[PhishingChecker] Error sending progress update to popup:', chrome.runtime.lastError.message);
        }
      });
      sendResponse({ success: true });
    } else {
      console.warn('[PhishingChecker] Unhandled message type:', message.type);
      sendResponse({ error: 'Unhandled message type' });
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

async function sendProgressUpdate(phase, percentage) {
  console.log('[PhishingChecker] Sending progress update:', phase, percentage);
  try {
    await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: 'progressUpdate', phase, percentage }, response => {
        if (chrome.runtime.lastError) {
          console.error('[PhishingChecker] Failed to send progress update:', chrome.runtime.lastError.message);
          reject(chrome.runtime.lastError);
        } else {
          console.log('[PhishingChecker] Progress update sent successfully:', phase, percentage);
          resolve(response);
        }
      });
    });
  } catch (err) {
    console.error('[PhishingChecker] Failed to send progress update:', err);
  }
}

async function analyzeEmail(emailData) {
  console.log('[PhishingChecker] Starting email analysis with data:', emailData);
  let score = 0;
  let warnings = [];

  let sender, content, links;
  try {
    sender = sanitizeString(emailData.sender?.toLowerCase() || '');
    content = sanitizeString(emailData.content?.toLowerCase() || '');
    links = (emailData.links || [])
      .slice(0, MAX_LINKS_TO_PROCESS)
      .map(link => sanitizeString(link))
      .filter(link => isValidUrl(link));
  } catch (err) {
    throw new Error('Failed to sanitize email data: ' + err.message);
  }

  if (!sender || !content) {
    throw new Error('Invalid email data: sender or content missing');
  }

  await sendProgressUpdate('Running heuristic analysis', 0);
  console.log('[PhishingChecker] Running heuristic analysis');
  try {
    const heuristicResult = checkPhishingHeuristics(sender, content, links, emailData.domain);
    score += heuristicResult.score;
    warnings.push(...heuristicResult.warnings);
  } catch (err) {
    warnings.push('Heuristic analysis failed: ' + err.message);
  }
  await sendProgressUpdate('Heuristic analysis completed', 50);

  await sendProgressUpdate('Finalizing results', 75);
  let riskLevel = 'Low';
  if (score > 70) riskLevel = 'High';
  else if (score > 40) riskLevel = 'Medium';

  await sendProgressUpdate('Analysis complete', 100);

  console.log('[PhishingChecker] Final analysis result:', { riskLevel, score: Math.min(score, 100), warnings });
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
