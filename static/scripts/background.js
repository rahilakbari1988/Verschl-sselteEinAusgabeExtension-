chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    debugger
  if (message.action === "getLoginStatus") {
    chrome.storage.session.get(["isLoggedIn"], (res) => {
      sendResponse({ isLoggedIn: res.isLoggedIn || false });
    });
    return true;
  }

  if (message.action === "getPrivateKey") {
    chrome.storage.session.get(["privateKey"], (res) => {
      sendResponse({ privateKey: res.privateKey || null });
    });
    return true;
  }

  if (message.action === "getPublicKey") {
    chrome.storage.session.get(["publicKey"], (res) => {
      sendResponse({ publicKey: res.publicKey || null });
    });
    return true;
  }
});
