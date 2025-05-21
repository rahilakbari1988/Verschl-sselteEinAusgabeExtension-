chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.action === "loginStatusChanged") {
    // Bei Login-Status-Änderung ggf. Inhalte anzeigen/verbergen
    if (!message.isLoggedIn) {
      hideEncryptedContent();
    }
  } else if (message.action === "encryptSelection") {
    encryptSelectedText();
  }
});

async function encryptSelectedText() {
  const selection = window.getSelection();
  if (!selection.toString()) {
    alert("Bitte wählen Sie Text aus.");
    return;
  }

  try {
    // Public Key aus Session holen
    const { publicKey } = await chrome.storage.session.get(['publicKey']);
    if (!publicKey) {
      alert("Nicht angemeldet.");
      return;
    }

    // Public Key importieren
    const publicKeyObj = await crypto.subtle.importKey(
      'spki',
      new Uint8Array(publicKey),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );

    // Text verschlüsseln
    const encoder = new TextEncoder();
    const data = encoder.encode(selection.toString());
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKeyObj,
      data
    );

    // Verschlüsselten Text als Base64 speichern
    const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    const encryptedElement = document.createElement('span');
    encryptedElement.className = 'encrypted-content';
    encryptedElement.textContent = `[Verschlüsselt: ${encryptedBase64}]`;
    selection.getRangeAt(0).deleteContents();
    selection.getRangeAt(0).insertNode(encryptedElement);
  } catch (error) {
    alert("Fehler bei der Verschlüsselung.");
  }
}

async function decryptContent(element) {
  const encryptedBase64 = element.textContent.match(/\[Verschlüsselt: (.*)\]/)?.[1];
  if (!encryptedBase64) return;

  try {
    // Private Key aus Session holen
    const { privateKey, isLoggedIn } = await chrome.storage.session.get(['privateKey', 'isLoggedIn']);
    if (!isLoggedIn || !privateKey) {
      alert("Nicht angemeldet.");
      return;
    }

    // Private Key importieren
    const privateKeyObj = await crypto.subtle.importKey(
      'pkcs8',
      new Uint8Array(privateKey),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );

    // Text entschlüsseln
    const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKeyObj,
      encrypted
    );
    const decoder = new TextDecoder();
    element.textContent = decoder.decode(decrypted);
    element.className = 'decrypted-content';
  } catch (error) {
    alert("Fehler bei der Entschlüsselung.");
  }
}

function hideEncryptedContent() {
  document.querySelectorAll('.encrypted-content').forEach(element => {
    element.style.display = 'none';
  });
}

// Entschlüsselung bei Klick auf verschlüsselte Inhalte
document.addEventListener('click', function(event) {
  if (event.target.classList.contains('encrypted-content')) {
    decryptContent(event.target);
  }
});

// Beim Laden der Seite verschlüsselte Inhalte ausblenden, wenn nicht eingeloggt
chrome.storage.session.get(['isLoggedIn'], function(data) {
  if (!data.isLoggedIn) {
    hideEncryptedContent();
  }
});