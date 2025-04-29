// Firebase configuration and initialization
/*const firebaseConfig = {
  apiKey: "YOUR_FIREBASE_API_KEY",
  authDomain: "YOUR_FIREBASE_AUTH_DOMAIN",
  projectId: "YOUR_FIREBASE_PROJECT_ID",
  storageBucket: "YOUR_FIREBASE_STORAGE_BUCKET",
  messagingSenderId: "YOUR_FIREBASE_MESSAGING_SENDER_ID",
  appId: "YOUR_FIREBASE_APP_ID"
};

let app, auth, db;
try {
  app = firebase.initializeApp(firebaseConfig);
  auth = firebase.auth();
  db = firebase.firestore();
} catch (err) {
  console.error('[PhishingChecker] Firebase initialization failed:', err);
  document.getElementById('status').textContent = 'Firebase unavailable. Using local storage.';
}*/

let isChecking = false;
let checkMessageListener = null;

document.addEventListener('DOMContentLoaded', () => {
  try {
    const checkButton = document.getElementById('checkButton');
    const cancelButton = document.getElementById('cancelButton');
    const statusDiv = document.getElementById('status');
    const progressBarContainer = document.getElementById('progressBarContainer');

    // Check if a previous check is in progress
    chrome.storage.local.get(['isChecking'], data => {
      if (data.isChecking) {
        startCheckUI();
      }
    });

    // Firebase Auth state listener (if Firebase is available)
    if (auth) {
      auth.onAuthStateChanged(user => {
        if (user) {
          // User is signed in, check ad-free status
          db.collection('users').doc(user.uid).get().then(doc => {
            if (doc.exists && doc.data().adFree) {
              chrome.storage.local.set({ adFreePurchased: true });
              document.getElementById('buyAdFreeButton').style.display = 'none';
            }
          }).catch(err => {
            console.error('[PhishingChecker] Firestore read failed:', err);
            // Fallback to local storage
            chrome.storage.local.get(['adFreePurchased'], data => {
              if (data.adFreePurchased) {
                document.getElementById('buyAdFreeButton').style.display = 'none';
              }
            });
          });
        } else {
          // No user signed in, prompt for sign-in
          signInWithGoogle();
        }
      });
    } else {
      // Fallback to local storage if Firebase is unavailable
      chrome.storage.local.get(['adFreePurchased'], data => {
        if (data.adFreePurchased) {
          document.getElementById('buyAdFreeButton').style.display = 'none';
        }
      });
    }

    checkButton.addEventListener('click', () => {
      if (!isChecking) {
        startCheckUI();
        chrome.storage.local.set({ isChecking: true });
        checkEmail();
      }
    });

    cancelButton.addEventListener('click', () => {
      stopCheckUI();
      chrome.storage.local.set({ isChecking: false });
      chrome.runtime.sendMessage({ type: 'cancelCheck' });
      if (checkMessageListener) {
        chrome.runtime.onMessage.removeListener(checkMessageListener);
        checkMessageListener = null;
      }
    });

    document.getElementById('buyAdFreeButton').addEventListener('click', () => {
      statusDiv.textContent = 'Redirecting to payment...';
      chrome.runtime.sendMessage({ type: 'initiatePayment' }, response => {
        if (response.checkoutUrl) {
          chrome.tabs.create({ url: response.checkoutUrl });
        } else {
          statusDiv.textContent = 'Error initiating payment. Please try again.';
        }
      });
    });

    document.getElementById('configButton').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });
  } catch (err) {
    console.error('[PhishingChecker] Popup initialization error:', err);
    document.getElementById('status').textContent = 'Error initializing popup. Please try again.';
  }
});

function signInWithGoogle() {
  if (!auth) {
    console.error('[PhishingChecker] Firebase Auth unavailable.');
    return;
  }
  const provider = new firebase.auth.GoogleAuthProvider();
  auth.signInWithRedirect(provider).catch(error => {
    console.error('[PhishingChecker] Sign-in error:', error);
    document.getElementById('status').textContent = 'Error signing in. Please try again.';
  });
}

function startCheckUI() {
  isChecking = true;
  document.getElementById('checkButton').style.display = 'none';
  document.getElementById('cancelButton').style.display = 'block';
  document.getElementById('progressBarContainer').style.display = 'block';
  document.getElementById('status').textContent = 'Checking email...';
}

function stopCheckUI() {
  isChecking = false;
  document.getElementById('checkButton').style.display = 'block';
  document.getElementById('cancelButton').style.display = 'none';
  document.getElementById('progressBarContainer').style.display = 'none';
  document.getElementById('status').textContent = 'Check cancelled.';
}

function checkEmail() {
  const statusDiv = document.getElementById('status');

  // Simplified check without ad requirement
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (!tabs || tabs.length === 0) {
      stopCheckUI();
      statusDiv.textContent = 'No active tab found. Please open an email and try again.';
      chrome.storage.local.set({ isChecking: false });
      return;
    }

    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      function: () => {
        chrome.runtime.sendMessage({ type: 'checkEmail' });
      }
    }, results => {
      if (chrome.runtime.lastError) {
        stopCheckUI();
        statusDiv.textContent = 'Failed to execute script. Check if you are on a supported email page (e.g., Gmail).';
        console.error('[PhishingChecker] Script execution error:', chrome.runtime.lastError);
        chrome.storage.local.set({ isChecking: false });
        return;
      }

      checkMessageListener = (message, sender, sendResponse) => {
        if (message.result) {
          stopCheckUI();
          statusDiv.innerHTML = DOMPurify.sanitize(`
            <strong>Risk Level: ${message.result.riskLevel}</strong><br>
            Score: ${message.result.score}<br>
            ${message.result.warnings.length ? message.result.warnings.join('<br>') : 'No warnings.'}
          `);
          chrome.storage.local.set({ isChecking: false });
        } else if (message.error) {
          stopCheckUI();
          statusDiv.textContent = 'Error during analysis: ' + message.error;
          console.error('[PhishingChecker] Analysis error:', message.error);
          chrome.storage.local.set({ isChecking: false });
        }
      };
      chrome.runtime.onMessage.addListener(checkMessageListener);
    });
  });
}