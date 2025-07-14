console.log("popup.js läuft");

document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('login-form');
  const loggedInView = document.getElementById('logged-in-view');
  const setupSection = document.getElementById('setup-section');
  const passwordInput = document.getElementById('password');
  const loginButton = document.getElementById('login-button');
  const setupButton = document.getElementById('setup-button');
  const logoutButton = document.getElementById('logout-button');
  const newPasswordInput = document.getElementById('new-password');
  const confirmPasswordInput = document.getElementById('confirm-password');
  const statusMessage = document.getElementById('status-message');

  // Check initial login state
  chrome.storage.local.get(['passwordHash', 'salt', 'publicKey', 'encryptedPrivateKey'], function(data) {
    if (!data.passwordHash) {
      setupSection.classList.remove('hidden');
      loginForm.classList.add('hidden');
    } else {
      chrome.storage.session.get(['isLoggedIn'], function(sessionData) {
        if (sessionData.isLoggedIn) {
          loginForm.classList.add('hidden');
          loggedInView.classList.remove('hidden');
        }
      });
    }
  });

  // Status message function
  function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = 'status ' + type;
    statusMessage.classList.remove('hidden');
    setTimeout(() => {
      statusMessage.classList.add('hidden');
    }, 3000);
  }

  // Array comparison function
  function compareArrays(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    for (let i = 0; i < arr1.length; i++) {
      if (arr1[i] !== arr2[i]) return false;
    }
    return true;
  }

  // Setup new password button
  setupButton.addEventListener('click', async () => {
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (newPassword !== confirmPassword) {
      showStatus('Passwörter stimmen nicht überein', 'error');
      return;
    }

    if (newPassword.length < 5) {
      showStatus('Passwort muss mindestens 5 Zeichen lang sein', 'error');
      return;
    }

    try {
      // Generate salt
      const salt = crypto.getRandomValues(new Uint8Array(16));

      // Create password hash
      const encoder = new TextEncoder();
      const passwordData = encoder.encode(newPassword);
      const saltedPassword = new Uint8Array([...passwordData, ...salt]);
      const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);

      // Generate RSA key pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      // Encrypt private key with password (AES-GCM)
      const passwordKey = await crypto.subtle.importKey(
        'raw',
        await crypto.subtle.digest('SHA-256', encoder.encode(newPassword)),
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedPrivateKey = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        passwordKey,
        exportedPrivateKey
      );

      // Export public key
      const exportedPublicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);

      // Convert data to arrays for storage
      const passwordHashArray = Array.from(new Uint8Array(passwordHash));
      const saltArray = Array.from(salt);
      const encryptedPrivateKeyArray = Array.from(new Uint8Array(encryptedPrivateKey));
      const ivArray = Array.from(iv);
      const publicKeyArray = Array.from(new Uint8Array(exportedPublicKey));

      // Store data in storage
      await new Promise((resolve, reject) => {
        chrome.storage.local.set({
          passwordHash: passwordHashArray,
          salt: saltArray,
          publicKey: publicKeyArray,
          encryptedPrivateKey: {
            data: encryptedPrivateKeyArray,
            iv: ivArray
          }
        }, () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        });
      });

      // Store login state in session
      await new Promise((resolve, reject) => {
        chrome.storage.session.set({
          isLoggedIn: true,
          privateKey: Array.from(new Uint8Array(exportedPrivateKey)),
          publicKey: Array.from(new Uint8Array(exportedPublicKey))
        }, () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        });
      });

      showStatus('Passwort erfolgreich erstellt!', 'success');
      setupSection.classList.add('hidden');
      loginForm.classList.add('hidden');
      loggedInView.classList.remove('hidden');

      // Send message to active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
         console.log("🔍 active tab:", tabs);
         console.log("sending message to tab", tabs[0].url);
        if (!tabs || tabs.length === 0) {
          showStatus('Kein aktiver Tab gefunden', 'error');
          return;
        }
        chrome.tabs.sendMessage(tabs[0].id, { action: "loginStatusChanged", isLoggedIn: true }, (response) => {
          if (chrome.runtime.lastError) {
            console.log('Message sending failed:', chrome.runtime.lastError);
          }
        });
      });
    } catch (error) {
      showStatus('Fehler beim Erstellen des Passworts: ' + error.message, 'error');
    }
  });

  // Login button
  loginButton.addEventListener('click', async () => {
    const password = passwordInput.value;

    if (!password) {
      showStatus('Bitte geben Sie das Passwort ein.', 'error');
      return;
    }

    try {
      const data = await new Promise((resolve, reject) => {
        chrome.storage.local.get(['passwordHash', 'salt', 'encryptedPrivateKey', 'publicKey'], (data) => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(data);
          }
        });
      });

      if (!data.passwordHash) {
        showStatus('Kein Passwort wurde konfiguriert.', 'error');
        return;
      }

      const encoder = new TextEncoder();
      const passwordData = encoder.encode(password);
      const salt = new Uint8Array(data.salt);
      const saltedPassword = new Uint8Array([...passwordData, ...salt]);
      const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);
      const passwordHashArray = Array.from(new Uint8Array(passwordHash));

      if (!compareArrays(passwordHashArray, data.passwordHash)) {
        showStatus('Das Passwort ist falsch.', 'error');
        return;
      }

      // Decrypt private key
      const passwordKey = await crypto.subtle.importKey(
        'raw',
        await crypto.subtle.digest('SHA-256', encoder.encode(password)),
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      const iv = new Uint8Array(data.encryptedPrivateKey.iv);
      const encryptedData = new Uint8Array(data.encryptedPrivateKey.data);

      const decryptedPrivateKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        passwordKey,
        encryptedData
      );

      // Import keys
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        decryptedPrivateKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['decrypt']
      );

      const publicKey = await crypto.subtle.importKey(
        'spki',
        new Uint8Array(data.publicKey),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
      );

      // Store in session
   // ابتدا کلیدها را استخراج کن
const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey);
const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);

// سپس در session ذخیره کن
await new Promise((resolve, reject) => {
  chrome.storage.session.set({
    isLoggedIn: true,
    privateKey: Array.from(new Uint8Array(exportedPrivateKey)),
    publicKey: Array.from(new Uint8Array(exportedPublicKey))
  }, () => {
    if (chrome.runtime.lastError) {
      console.error("❌ خطا در ذخیره session:", chrome.runtime.lastError.message);
      reject(chrome.runtime.lastError);
    } else {
      console.log("✅ کلیدها در session ذخیره شدند.");
      resolve();
    }
  });
});

      showStatus('Sie haben sich erfolgreich angemeldet!', 'success');
      loginForm.classList.add('hidden');
      loggedInView.classList.remove('hidden');

      // Send message to active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
          showStatus('Kein aktiver Tab gefunden', 'error');
          return;
        }
        chrome.tabs.sendMessage(tabs[0].id, { action: "loginStatusChanged", isLoggedIn: true }, (response) => {
          if (chrome.runtime.lastError) {
            console.log('Message sending failed:', chrome.runtime.lastError);
          }
        });
      });
    } catch (error) {
      showStatus('Anmeldefehler: ' + error.message, 'error');
    }
  });

  // Logout button
  logoutButton.addEventListener('click', async () => {
    try {
      await new Promise((resolve, reject) => {
        chrome.storage.session.clear(() => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        });
      });

      showStatus('Sie wurden erfolgreich abgemeldet!', 'success');
      loggedInView.classList.add('hidden');
      loginForm.classList.remove('hidden');
      passwordInput.value = '';

      // Send message to active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
          return;
        }
        chrome.tabs.sendMessage(tabs[0].id, { action: "loginStatusChanged", isLoggedIn: false }, (response) => {
          if (chrome.runtime.lastError) {
            console.log('Message sending failed:', chrome.runtime.lastError);
          }
        });
      });
    } catch (error) {
      showStatus('Abmeldefehler: ' + error.message, 'error');
    }
  });

  // Enter key support for password inputs
  passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      loginButton.click();
    }
  });

  confirmPasswordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      setupButton.click();
    }
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const copyBtn = document.getElementById("copyPublicKeyBtn");
  const output = document.getElementById("publicKeyOut");

  if (copyBtn && output) {
    copyBtn.addEventListener("click", () => {
      chrome.storage.session.get("publicKey", (res) => {
        if (!res.publicKey) return alert("🔑 کلید عمومی موجود نیست. اول login کن.");
        const uint8 = new Uint8Array(res.publicKey);
        const base64 = btoa(String.fromCharCode(...uint8));
        output.value = base64;
      });
    });
  }
});
document.addEventListener("DOMContentLoaded", () => {
  const encryptBtn = document.getElementById("encryptBtn");
  const input = document.getElementById("encryptTextInput");
  const output = document.getElementById("encryptedOutput");

  if (encryptBtn && input && output) {
    encryptBtn.addEventListener("click", async () => {
      chrome.storage.session.get("publicKey", async (res) => {
        if (!res.publicKey) return alert("کلید عمومی موجود نیست. اول login کن.");

        const rawKey = new Uint8Array(res.publicKey);
        const publicKey = await crypto.subtle.importKey(
          "spki",
          rawKey,
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        );

        const encoded = new TextEncoder().encode(input.value);
        const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encoded);
        const encryptedArray = Array.from(new Uint8Array(encrypted));
        const divHTML = `<div data-encrypted='${JSON.stringify({ data: encryptedArray })}'>[Verschlüsselter Inhalt - Anmeldung erforderlich]</div>`;
        output.value = divHTML;
      });
    });
  }
});
