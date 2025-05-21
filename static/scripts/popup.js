document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('login-form');
  const loggedInView = document.getElementById('logged-in-view');
  const setupSection = document.getElementById('setup-section');
  const passwordInput = document.getElementById('password');
  const loginButton = document.getElementById('login-button');
  const setupButton = document.getElementById('setup-button');
  const newPasswordInput = document.getElementById('new-password');
  const confirmPasswordInput = document.getElementById('confirm-password');
  const statusMessage = document.getElementById('status-message');

  // first check if user are login
  chrome.storage.local.get(['passwordHash', 'salt', 'publicKey', 'encryptedPrivateKey'], function(data) {
    if (!data.passwordHash) {
      setupSection.classList.remove('hidden');
      loginForm.classList.add('hidden');
    } else {
      chrome.storage.session.get(['isLoggedIn'], function(data) {
        if (data.isLoggedIn) {
          loginForm.classList.add('hidden');
          loggedInView.classList.remove('hidden');
        }
      });
    }
  });

  // set pass
  setupButton.addEventListener('click', async function() {
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    if (newPassword !== confirmPassword) {
      showStatus('Passwords do not match', 'error');
      return;
    }
    
    if (newPassword.length < 5) {
      showStatus('Password must be at least 5 characters', 'error');
      return;
    }
    
    try {
      // create salt
      const salt = crypto.getRandomValues(new Uint8Array(16));
      
      // create hash
      const encoder = new TextEncoder();
      const passwordData = encoder.encode(newPassword);
      const saltedPassword = new Uint8Array([...passwordData, ...salt]);
      const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);
      
      // create key
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
      
      // Encrypt the private key with a password
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
      
      // Public key extraction
      const exportedPublicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      
      // Convert to array for storage
      const passwordHashArray = Array.from(new Uint8Array(passwordHash));
      const saltArray = Array.from(salt);
      const encryptedPrivateKeyArray = Array.from(new Uint8Array(encryptedPrivateKey));
      const ivArray = Array.from(iv);
      const publicKeyArray = Array.from(new Uint8Array(exportedPublicKey));
      
      // Data storage
      chrome.storage.local.set({
        passwordHash: passwordHashArray,
        salt: saltArray,
        publicKey: publicKeyArray,
        encryptedPrivateKey: {
          data: encryptedPrivateKeyArray,
          iv: ivArray
        }
      }, function() {
        // Save session status
        chrome.storage.session.set({
          isLoggedIn: true,
          privateKey: exportedPrivateKey,
          publicKey: exportedPublicKey
        }, function() {
          showStatus('Password created successfully!', 'success');
          setupSection.classList.add('hidden');
          loginForm.classList.add('hidden');
          loggedInView.classList.remove('hidden');
          
          // Notification to content script
          chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs && tabs[0] && tabs[0].id) {
              chrome.tabs.sendMessage(tabs[0].id, {action: "loginStatusChanged", isLoggedIn: true});
            }
          });
        });
      });
    } catch (error) {
      showStatus('Error setting password' + error.message, 'error');
    }
  });

  // Login
  loginButton.addEventListener('click', async function() {
    const password = passwordInput.value;
    
    if (!password) {
      showStatus('Please enter the password.', 'error');
      return;
    }
    
    try {
      chrome.storage.local.get(['passwordHash', 'salt', 'encryptedPrivateKey', 'publicKey'], async function(data) {
        if (!data.passwordHash) {
          showStatus('No password has been set.', 'error');
          return;
        }
        
        // Password check
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        const salt = new Uint8Array(data.salt);
        const saltedPassword = new Uint8Array([...passwordData, ...salt]);
        const passwordHash = await crypto.subtle.digest('SHA-256', saltedPassword);
        const passwordHashArray = Array.from(new Uint8Array(passwordHash));
        
        // Comparing password hashes
        if (!compareArrays(passwordHashArray, data.passwordHash)) {
          showStatus('The password is incorrect.', 'error');
          return;
        }
        
        // Decryption of the private key
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
        
        // Entering keys
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
        
        // Storing keys in session memory
        await chrome.storage.session.set({
          isLoggedIn: true,
          privateKey: await crypto.subtle.exportKey('pkcs8', privateKey),
          publicKey: await crypto.subtle.exportKey('spki', publicKey)
        });
        
        showStatus('You have successfully logged in!', 'success');
        loginForm.classList.add('hidden');
        loggedInView.classList.remove('hidden');
        
        // Notification to content script
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
          if (tabs && tabs[0] && tabs[0].id) {
            chrome.tabs.sendMessage(tabs[0].id, {action: "loginStatusChanged", isLoggedIn: true});
          }
        });
      });
    } catch (error) {
      showStatus('Login error', 'error');
    }
  });

  // Helper function for displaying message
  function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = 'status ' + type;
    statusMessage.classList.remove('hidden');
    
    setTimeout(function() {
      statusMessage.classList.add('hidden');
    }, 3000);
  }
  
  //Helper function for comparing arrays
  function compareArrays(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    for (let i = 0; i < arr1.length; i++) {
      if (arr1[i] !== arr2[i]) return false;
    }
    return true;
  }
});