console.log("content.js läuft");
chrome.runtime.sendMessage({ action: "getPrivateKey" }, (response) => {
  console.log(" private key response:", response);
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "loginStatusChanged") {
    if (message.isLoggedIn) {
      decryptAllEncryptedElements();
    } else {
      hideEncryptedPlaceholders();
    }
  }
});

// اجرای اولیه
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', checkLoginStatusAndInitialize);
} else {
  checkLoginStatusAndInitialize();
}

function checkLoginStatusAndInitialize() {
  chrome.runtime.sendMessage({ action: "getLoginStatus" }, (response) => {
    if (response?.isLoggedIn) {
      decryptAllEncryptedElements();
    } else {
      hideEncryptedPlaceholders();
    }
  });
}

function hideEncryptedPlaceholders() {
  const elements = document.querySelectorAll('[data-encrypted]');
  elements.forEach(el => {
    el.textContent = '[Verschlüsselter 255Inhalt - Anmeldung erforderlich]';
    el.style.backgroundColor = '#fff3cd';
    el.style.border = '1px dashed #856404';
    el.style.padding = '2px 4px';
    el.style.fontStyle = 'italic';
  });
}

async function decryptAllEncryptedElements() {
  chrome.runtime.sendMessage({ action: "getPrivateKey" }, async (response) => {
    if (!response?.privateKey) {
      console.warn("❌ privateKey موجود نیست.");
      return;
    }

    try {
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        new Uint8Array(response.privateKey),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['decrypt']
      );

      console.log("✅ privateKey imported.");

      const elements = document.querySelectorAll('[data-encrypted]');
      for (const el of elements) {
        try {
          const data = JSON.parse(el.dataset.encrypted);
          const ciphertext = new Uint8Array(data.data || data);

          const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            ciphertext
          );

          el.textContent = new TextDecoder().decode(decrypted);
          el.style.backgroundColor = '#e8f5e8';
          el.style.border = '1px dashed green';
          el.style.padding = '2px 4px';

        } catch (e) {
          console.error("❌ خطا در رمزگشایی این عنصر:", e);
          el.textContent = '[Fehler beim Entschlüsseln]';
          el.style.color = 'red';
        }
      }
    } catch (err) {
      console.error("❌ خطا در import کردن کلید:", err);
    }
  });
}
