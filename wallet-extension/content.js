(() => {
  const request = (method, params = []) => new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const listener = event => {
      if (event.source !== window || !event.data || event.data.type !== 'TENEBRA_WALLET_RESPONSE' || event.data.requestId !== requestId) return;
      window.removeEventListener('message', listener);
      if (event.data.error) reject(new Error(event.data.error));
      else resolve(event.data.result);
    };
    window.addEventListener('message', listener);
    window.postMessage({ type: 'TENEBRA_WALLET_REQUEST', requestId, method, params }, '*');
  });

  window.tenebraWallet = {
    request,
    getNetworks: () => request('tenebra_getNetworks'),
    getSupportedChains: () => request('tenebra_getSupportedChains'),
    validateAddress: (chainId, value) => request('tenebra_validateAddress', [chainId, value]),
    createDepositRequest: (chainId, input) => request('tenebra_createDepositRequest', [chainId, input]),
    createWithdrawalRequest: (chainId, input) => request('tenebra_createWithdrawalRequest', [chainId, input]),
    createTransferRequest: (chainId, input) => request('tenebra_createTransferRequest', [chainId, input]),
    addNetwork: network => request('tenebra_addNetwork', [network]),
    removeNetwork: networkId => request('tenebra_removeNetwork', [networkId]),
  };

  window.addEventListener('message', event => {
    if (event.source !== window || !event.data || event.data.type !== 'TENEBRA_WALLET_REQUEST') return;
    chrome.runtime.sendMessage(event.data);
  });

  chrome.runtime.onMessage.addListener(message => {
    if (message && message.type === 'TENEBRA_WALLET_RESPONSE') window.postMessage(message, '*');
  });
})();
