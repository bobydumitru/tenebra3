(() => {
  const pending = new Map();
  window.addEventListener('message', event => {
    if (event.source !== window || !event.data || event.data.type !== 'TENEBRA_WALLET_REQUEST') return;
    const { requestId, method, params } = event.data;
    chrome.runtime.sendMessage({ type: 'TENEBRA_WALLET_REQUEST', requestId, method, params });
  });

  chrome.runtime.onMessage.addListener(message => {
    if (!message || message.type !== 'TENEBRA_WALLET_RESPONSE') return;
    window.postMessage(message, '*');
  });
})();
