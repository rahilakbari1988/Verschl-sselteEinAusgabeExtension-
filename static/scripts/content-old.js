// Kommunikation mit Popup aufbauen
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "loginStatusChanged") {
    console.log("Login-Status geändert:", request.isLoggedIn);
    if (request.isLoggedIn) {
      // Optional: Automatisch verschlüsselte Inhalte auf der Seite entschlüsseln
      decryptPageContent();
    }
  } else if (request.action === "encryptSelection") {
    encryptSelectedText();
  }
  
  // Immer eine Antwort senden, um die Verbindung nicht zu schließen
  sendResponse({status: "received"});
  return true;
});

// Funktion zum Verschlüsseln des ausgewählten Textes
async function encryptSelectedText() {
  const selection = window.getSelection();
  if (!selection.toString().trim()) {
    alert("Bitte wählen Sie zuerst Text aus, um ihn zu verschlüsseln.");
    return;
  }
  
  try {
    // Prüfen, ob eingeloggt und Public Key verfügbar
    const result = await chrome.storage.session.get(['isLoggedIn', 'publicKey']);
    
    if (!result.isLoggedIn || !result.publicKey) {
      alert("Bitte melden Sie sich zuerst an, um Text zu verschlüsseln.");
      return;
    }
    
    const selectedText = selection.toString();
    
    // Public Key importieren
    const publicKey = await crypto.subtle.importKey(
      'spki',
      result.publicKey,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['encrypt']
    );
    
    // Text in Chunks verschlüsseln, da RSA-OAEP Größenbeschränkungen hat
    const encoder = new TextEncoder();
    const data = encoder.encode(selectedText);
    
    // Für eine einfache Implementierung verschlüsseln wir den gesamten Text
    // In einer vollständigen Version sollte hier eine Chunk-Verarbeitung erfolgen
    // wenn der Text zu lang ist
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      publicKey,
      data
    );
    
    // Verschlüsselte Daten in Base64 umwandeln
    const encryptedBase64 = arrayBufferToBase64(encryptedData);
    
    // Verschlüsselten Text in HTML-Element einbetten
    const range = selection.getRangeAt(0);
    range.deleteContents();
    
    const encryptedElement = document.createElement('span');
    encryptedElement.className = 'secure-content-encrypted';
    encryptedElement.setAttribute('data-encrypted', encryptedBase64);
    encryptedElement.style.backgroundColor = '#f0f0f0';
    encryptedElement.style.padding = '2px 5px';
    encryptedElement.style.borderRadius = '3px';
    encryptedElement.textContent = '🔒 [Verschlüsselter Inhalt]';
    
    range.insertNode(encryptedElement);
    
    alert("Text wurde erfolgreich verschlüsselt!");
  } catch (error) {
    console.error('Fehler bei der Textverschlüsselung:', error);
    alert("Fehler bei der Verschlüsselung des Textes.");
  }
}

// Funktion zum Entschlüsseln aller verschlüsselten Inhalte auf der Seite
async function decryptPageContent() {
  try {
    // Prüfen, ob eingeloggt und Private Key verfügbar
    const result = await chrome.storage.session.get(['isLoggedIn', 'privateKey']);
    
    if (!result.isLoggedIn || !result.privateKey) {
      return; // Nicht eingeloggt oder kein Schlüssel verfügbar
    }
    
    // Private Key importieren
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      result.privateKey,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['decrypt']
    );
    
    // Alle verschlüsselten Elemente finden und entschlüsseln
    const encryptedElements = document.querySelectorAll('.secure-content-encrypted');
    
    for (let element of encryptedElements) {
      const encryptedBase64 = element.getAttribute('data-encrypted');
      if (!encryptedBase64) continue;
      
      try {
        const encryptedData = base64ToArrayBuffer(encryptedBase64);
        
        // Daten entschlüsseln
        const decryptedData = await crypto.subtle.decrypt(
          {
            name: 'RSA-OAEP'
          },
          privateKey,
          encryptedData
        );
        
        // Entschlüsselte Daten in Text umwandeln
        const decoder = new TextDecoder();
        const decryptedText = decoder.decode(decryptedData);
        
        // Element aktualisieren
        element.textContent = decryptedText;
        element.style.backgroundColor = '#e6f7ff';
        element.title = 'Entschlüsselter Inhalt';
      } catch (error) {
        console.error('Fehler bei der Entschlüsselung eines Elements:', error);
        element.textContent = '🔒 [Entschlüsselungsfehler]';
        element.style.backgroundColor = '#ffeeee';
      }
    }
  } catch (error) {
    console.error('Fehler bei der Seitenentschlüsselung:', error);
  }
}

// Hilfsfunktionen für Base64-Konvertierung
function arrayBufferToBase64(buffer) {
  const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Initial prüfen, ob eingeloggt und ggf. verschlüsselte Inhalte entschlüsseln
chrome.storage.session.get(['isLoggedIn'], function(result) {
  if (result.isLoggedIn) {
    decryptPageContent();
  }
});