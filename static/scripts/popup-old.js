document.addEventListener('DOMContentLoaded', function() {
  debugger
  const loginForm = document.getElementById('login-form');
  const loggedInView = document.getElementById('logged-in-view');
  const setupSection = document.getElementById('setup-section');
  const passwordInput = document.getElementById('password');
  const loginButton = document.getElementById('login-button');
  const logoutButton = document.getElementById('logout-button');
  const encryptSelectionButton = document.getElementById('encrypt-selection-button');
  const statusMessage = document.getElementById('status-message');
  const setupButton = document.getElementById('setup-button');
  const newPasswordInput = document.getElementById('new-password');
  const confirmPasswordInput = document.getElementById('confirm-password');

  // Make sure the chrome API is available before using it
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      showStatus('Chrome extension APIs not available. Are you running this in a Chrome extension?', 'error');
      return;
  }

  // Überprüfe, ob bereits ein Passwort eingerichtet wurde
  chrome.storage.local.get(['passwordHash', 'salt', 'publicKey', 'encryptedPrivateKey'], function(data) {
    debugger
    if (!data.passwordHash || !data.salt || !data.publicKey || !data.encryptedPrivateKey) {
      setupSection.classList.remove('hidden');
      loginForm.classList.add('hidden');
    } else {
      // Überprüfe, ob bereits eingeloggt
      chrome.storage.session.get(['isLoggedIn'], function(data) {
        if (data.isLoggedIn) {
          loginForm.classList.add('hidden');
          loggedInView.classList.remove('hidden');
        }
      });
    }
  });

  // Passwort einrichten
  setupButton.addEventListener('click', async function() {
    debugger
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    if (newPassword !== confirmPassword) {
      showStatus('Die Passwörter stimmen nicht überein.', 'error');
      return;
    }
    
    if (newPassword.length < 8) {
      showStatus('Das Passwort muss mindestens 8 Zeichen lang sein.', 'error');
      return;
    }
    
    try {
      console.log("Starting password setup...");
      
      // Salt für Passwort-Hashing generieren
      const salt = crypto.getRandomValues(new Uint8Array(16));
      console.log("Salt generated");
      
      // Passwort-Hash erstellen
      const encoder = new TextEncoder();
      const passwordData = encoder.encode(newPassword);
      const saltedPassword = new Uint8Array([...passwordData, ...salt]);
      const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);
      console.log("Password hash created");
      
      // Schlüsselpaar für asymmetrische Verschlüsselung generieren
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
      console.log("Key pair generated");
      
      // Private Key mit symmetrischem Schlüssel aus Passwort verschlüsseln
      const passwordKey = await crypto.subtle.importKey(
        'raw',
        await crypto.subtle.digest('SHA-256', encoder.encode(newPassword)),
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      console.log("Password key created");
      
      const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      console.log("Private key exported");
      
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedPrivateKey = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        passwordKey,
        exportedPrivateKey
      );
      console.log("Private key encrypted");
      
      // Export public key
      const exportedPublicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      console.log("Public key exported");
      
      // Convert ArrayBuffer to Array for storage
      const passwordHashArray = Array.from(new Uint8Array(passwordHash));
      const saltArray = Array.from(salt);
      const encryptedPrivateKeyArray = Array.from(new Uint8Array(encryptedPrivateKey));
      const ivArray = Array.from(iv);
      const publicKeyArray = Array.from(new Uint8Array(exportedPublicKey));
      
      // Daten speichern - use callback for better error handling
      chrome.storage.local.set({
        passwordHash: passwordHashArray,
        salt: saltArray,
        publicKey: publicKeyArray,
        encryptedPrivateKey: {
          data: encryptedPrivateKeyArray,
          iv: ivArray
        }
      }, function() {
        if (chrome.runtime.lastError) {
          console.error("Error saving to local storage:", chrome.runtime.lastError);
          showStatus('Fehler beim Speichern: ' + chrome.runtime.lastError.message, 'error');
          return;
        }
        
        console.log("Data saved to local storage");
        
        // Session-Daten speichern
        chrome.storage.session.set({
          isLoggedIn: true,
          privateKey: exportedPrivateKey,
          publicKey: exportedPublicKey
        }, function() {
          if (chrome.runtime.lastError) {
            console.error("Error saving to session storage:", chrome.runtime.lastError);
            showStatus('Fehler beim Session-Speichern: ' + chrome.runtime.lastError.message, 'error');
            return;
          }
          
          console.log("Session data saved");
          showStatus('Passwort erfolgreich erstellt!', 'success');
          setupSection.classList.add('hidden');
          loginForm.classList.add('hidden');
          loggedInView.classList.remove('hidden');
          
          // Informiere den Content-Script über den Login-Status
          chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs && tabs[0] && tabs[0].id) {
              chrome.tabs.sendMessage(tabs[0].id, {action: "loginStatusChanged", isLoggedIn: true})
                .catch(err => console.error("Error sending message to tab:", err));
            }
          });
        });
      });
    } catch (error) {
      console.error('Fehler bei der Schlüsselerstellung:', error);
      showStatus('Fehler bei der Passwort-Einrichtung: ' + error.message, 'error');
    }
  });

  // Login-Funktion
  loginButton.addEventListener('click', async function() {
    const password = passwordInput.value;
    
    if (!password) {
      showStatus('Bitte geben Sie ein Passwort ein.', 'error');
      return;
    }
    
    try {
      chrome.storage.local.get(['passwordHash', 'salt', 'encryptedPrivateKey', 'publicKey'], async function(data) {
        if (!data.passwordHash || !data.salt || !data.encryptedPrivateKey || !data.publicKey) {
          showStatus('Kein Passwort eingerichtet.', 'error');
          return;
        }
        
        // Überprüfe Passwort
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        const salt = new Uint8Array(data.salt);
        const saltedPassword = new Uint8Array([...passwordData, ...salt]);
        const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);
        const passwordHashArray = Array.from(new Uint8Array(passwordHash));
        
        // Vergleiche Passwort-Hashes
        if (!compareArrays(passwordHashArray, data.passwordHash)) {
          showStatus('Falsches Passwort.', 'error');
          return;
        }
        
        // Private Key entschlüsseln
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
          {
            name: 'AES-GCM',
            iv: iv
          },
          passwordKey,
          encryptedData
        );
        
        // Private Key importieren
        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          decryptedPrivateKey,
          {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
          },
          true,
          ['decrypt']
        );
        
        // Public Key importieren
        const publicKey = await crypto.subtle.importKey(
          'spki',
          data.publicKey,
          {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
          },
          true,
          ['encrypt']
        );
        
        // Speichere Keys in Session Storage
        await chrome.storage.session.set({
          isLoggedIn: true,
          privateKey: await crypto.subtle.exportKey('pkcs8', privateKey),
          publicKey: await crypto.subtle.exportKey('spki', publicKey)
        });
        
        showStatus('Erfolgreich angemeldet!', 'success');
        loginForm.classList.add('hidden');
        loggedInView.classList.remove('hidden');
        
        // Informiere den Content-Script über den Login-Status
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
          if (tabs && tabs[0] && tabs[0].id) {
            chrome.tabs.sendMessage(tabs[0].id, {action: "loginStatusChanged", isLoggedIn: true})
              .catch(err => console.error("Error sending message to tab:", err));
          }
        });
      });
    } catch (error) {
      console.error('Login-Fehler:', error);
      showStatus('Fehler bei der Anmeldung.', 'error');
    }
  });

  // Logout-Funktion
  logoutButton.addEventListener('click', function() {
    debugger
    chrome.storage.session.remove(['isLoggedIn', 'privateKey', 'publicKey'], function() {
      loginForm.classList.remove('hidden');
      loggedInView.classList.add('hidden');
      passwordInput.value = '';
      
      // Informiere den Content-Script über den Logout
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs && tabs[0] && tabs[0].id) {
          chrome.tabs.sendMessage(tabs[0].id, {action: "loginStatusChanged", isLoggedIn: false})
            .catch(err => console.error("Error sending message to tab:", err));
        }
      });
      
      showStatus('Abgemeldet.', 'success');
    });
  });

  // Text-Verschlüsselung für markierten Text
  encryptSelectionButton.addEventListener('click', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs && tabs[0] && tabs[0].id) {
        chrome.tabs.sendMessage(tabs[0].id, {action: "encryptSelection"})
          .catch(err => console.error("Error sending message to tab:", err));
      }
    });
  });

  // Hilfsfunktionen
  function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = 'status ' + type;
    statusMessage.classList.remove('hidden');
    
    setTimeout(function() {
      statusMessage.classList.add('hidden');
    }, 3000);
  }
  
  function compareArrays(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    for (let i = 0; i < arr1.length; i++) {
      if (arr1[i] !== arr2[i]) return false;
    }
    return true;
  }
});