const TENEBRA_CHAIN_ID = 'TSC-1';
const MULTICHAIN_REGISTRY = {
  solana: { id: 'solana', label: 'Solana', symbol: 'SOL', addressPattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, requiredConfirmations: 32, finality: 'confirmed', supportsDeposit: true, supportsWithdrawal: true, adapter: 'solana' },
  evm: { id: 'evm', label: 'Ethereum / EVM', symbol: 'ETH', addressPattern: /^0x[a-fA-F0-9]{40}$/, requiredConfirmations: 12, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'evm' },
  bnb: { id: 'bnb', label: 'BNB Chain', symbol: 'BNB', addressPattern: /^0x[a-fA-F0-9]{40}$/, requiredConfirmations: 15, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'bnb' },
  avalanche: { id: 'avalanche', label: 'Avalanche C-Chain', symbol: 'AVAX', addressPattern: /^0x[a-fA-F0-9]{40}$/, requiredConfirmations: 12, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'avalanche' },
  arbitrum: { id: 'arbitrum', label: 'Arbitrum One', symbol: 'ETH', addressPattern: /^0x[a-fA-F0-9]{40}$/, requiredConfirmations: 20, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'arbitrum' },
  ton: { id: 'ton', label: 'TON', symbol: 'TON', addressPattern: /^[A-Za-z0-9_-]{40,70}$/, requiredConfirmations: 1, finality: 'confirmed', supportsDeposit: true, supportsWithdrawal: true, adapter: 'ton' },
  bitcoin: { id: 'bitcoin', label: 'Bitcoin', symbol: 'BTC', addressPattern: /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/, requiredConfirmations: 3, finality: 'confirmed', supportsDeposit: true, supportsWithdrawal: true, adapter: 'bitcoin' },
};
let wasm;
let walletFile = null;
let walletPassword = null;

async function loadWasm() {
  if (wasm) return wasm;
  const module = await import(chrome.runtime.getURL('wallet-wasm/tenebra_wallet_wasm.js'));
  wasm = await module.default();
  globalThis.walletWasm = wasm;
  globalThis.__TENEBRA_WASM_MEMORY = wasm.memory;
  return wasm;
}

function bytesToHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hexToBytes(value) {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error('Identificator TENEBRA invalid.');
  return Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
}

async function walletAddress() {
  if (!walletFile || !walletPassword) throw new Error('Wallet TENEBRA blocat. Deschide extensia și deblochează wallet-ul.');
  const instance = await loadWasm();
  const memory = instance.memory;
  const filePtr = instance.wallet_alloc(walletFile.length);
  const passwordBytes = new TextEncoder().encode(walletPassword);
  const passwordPtr = instance.wallet_alloc(passwordBytes.length);
  const outputPtr = instance.wallet_alloc(160);
  new Uint8Array(memory.buffer).set(walletFile, filePtr);
  new Uint8Array(memory.buffer).set(passwordBytes, passwordPtr);
  const length = instance.wallet_native_file_address(filePtr, passwordPtr, passwordBytes.length, outputPtr);
  if (!length) throw new Error('Parolă greșită sau wallet invalid.');
  return new TextDecoder().decode(new Uint8Array(memory.buffer.slice(outputPtr, outputPtr + length)));
}

async function signMessage(message) {
  if (!walletFile || !walletPassword) throw new Error('Wallet TENEBRA blocat.');
  const instance = await loadWasm();
  const memory = instance.memory;
  const filePtr = instance.wallet_alloc(walletFile.length);
  const passwordBytes = new TextEncoder().encode(walletPassword);
  const messageBytes = new TextEncoder().encode(String(message));
  const passwordPtr = instance.wallet_alloc(passwordBytes.length);
  const messagePtr = instance.wallet_alloc(messageBytes.length);
  const outputPtr = instance.wallet_alloc(64);
  new Uint8Array(memory.buffer).set(walletFile, filePtr);
  new Uint8Array(memory.buffer).set(passwordBytes, passwordPtr);
  new Uint8Array(memory.buffer).set(messageBytes, messagePtr);
  const length = instance.wallet_native_file_sign_message(filePtr, passwordPtr, passwordBytes.length, messagePtr, messageBytes.length, outputPtr);
  if (length !== 64) throw new Error('Semnarea mesajului a eșuat.');
  return bytesToBase64(new Uint8Array(memory.buffer.slice(outputPtr, outputPtr + length)));
}

async function signDex(method, params) {
  if (!walletFile || !walletPassword) throw new Error('Wallet TENEBRA blocat.');
  const instance = await loadWasm();
  const memory = instance.memory;
  const passwordBytes = new TextEncoder().encode(walletPassword);
  const filePtr = instance.wallet_alloc(walletFile.length);
  const passwordPtr = instance.wallet_alloc(passwordBytes.length);
  const outputPtr = instance.wallet_alloc(512);
  new Uint8Array(memory.buffer).set(walletFile, filePtr);
  new Uint8Array(memory.buffer).set(passwordBytes, passwordPtr);
  let length;
  if (method === 'tenebra_signDexCreatePool') {
    const assetA = hexToBytes(params.assetA), assetB = hexToBytes(params.assetB);
    const assetAPtr = instance.wallet_alloc(32), assetBPtr = instance.wallet_alloc(32);
    new Uint8Array(memory.buffer).set(assetA, assetAPtr); new Uint8Array(memory.buffer).set(assetB, assetBPtr);
    length = instance.wallet_native_file_sign_dex_create_pool(filePtr, passwordPtr, passwordBytes.length, assetAPtr, assetBPtr, BigInt(params.amountA), BigInt(params.amountB), BigInt(params.sequence), outputPtr);
  } else if (method === 'tenebra_signDexSwap') {
    const pool = hexToBytes(params.poolId), input = hexToBytes(params.inputAsset);
    const poolPtr = instance.wallet_alloc(32), inputPtr = instance.wallet_alloc(32);
    new Uint8Array(memory.buffer).set(pool, poolPtr); new Uint8Array(memory.buffer).set(input, inputPtr);
    length = instance.wallet_native_file_sign_dex_swap(filePtr, passwordPtr, passwordBytes.length, poolPtr, inputPtr, BigInt(params.inputAmount), BigInt(params.minOutput), BigInt(params.sequence), outputPtr);
  } else {
    const pool = hexToBytes(params.poolId);
    const poolPtr = instance.wallet_alloc(32);
    new Uint8Array(memory.buffer).set(pool, poolPtr);
    length = instance.wallet_native_file_sign_dex_remove_liquidity(filePtr, passwordPtr, passwordBytes.length, poolPtr, Number(params.shareBps), BigInt(params.sequence), outputPtr);
  }
  if (!length) throw new Error('Wallet-ul nu a putut semna operația.');
  return bytesToBase64(new Uint8Array(memory.buffer.slice(outputPtr, outputPtr + length)));
}

function normalizeChainId(chainId) {
  return String(chainId || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'custom';
}

function validateAddress(chainId, value) {
  const key = normalizeChainId(chainId);
  const chain = MULTICHAIN_REGISTRY[key];
  const address = String(value || '').trim();

  if (!chain) return { valid: false, reason: 'Rețeaua nu este suportată.' };
  if (!address) return { valid: false, reason: 'Adresa este goală.' };
  if (!chain.addressPattern.test(address)) return { valid: false, reason: `Adresă invalidă pentru ${chain.label}.` };
  return { valid: true, normalized: address };
}

function createDepositRequest(chainId, input) {
  const key = normalizeChainId(chainId);
  const chain = MULTICHAIN_REGISTRY[key];
  if (!chain) throw new Error('Rețeaua nu este suportată pentru depozit.');
  const amount = Number(input && input.amount);
  const address = validateAddress(key, input && input.address);
  if (!address.valid) throw new Error(address.reason);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('Suma de depozit este invalidă.');
  return {
    chainId: chain.id,
    type: 'deposit',
    amount,
    recipient: address.normalized,
    vault: input && input.vault ? String(input.vault).trim() : null,
    requiredConfirmations: chain.requiredConfirmations,
    finality: chain.finality,
    status: 'pending-verification',
    adapter: chain.adapter,
  };
}

function createWithdrawalRequest(chainId, input) {
  const key = normalizeChainId(chainId);
  const chain = MULTICHAIN_REGISTRY[key];
  if (!chain) throw new Error('Rețeaua nu este suportată pentru retragere.');
  const amount = Number(input && input.amount);
  const recipient = validateAddress(key, input && input.recipient);
  if (!recipient.valid) throw new Error(recipient.reason);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('Suma de retragere este invalidă.');
  return {
    chainId: chain.id,
    type: 'withdrawal',
    amount,
    recipient: recipient.normalized,
    source: input && input.source ? String(input.source).trim() : 'wallet',
    requiredConfirmations: chain.requiredConfirmations,
    finality: chain.finality,
    status: 'pending-verification',
    adapter: chain.adapter,
  };
}

function createTransferRequest(chainId, input) {
  const type = String(input && input.type || '').trim().toLowerCase();
  if (type === 'deposit') return createDepositRequest(chainId, input);
  if (type === 'withdrawal') return createWithdrawalRequest(chainId, input);
  const chain = MULTICHAIN_REGISTRY[normalizeChainId(chainId)];
  if (!chain) throw new Error('Rețeaua nu este suportată pentru transfer.');
  throw new Error('Tipul de transfer este invalid. Folosește "deposit" sau "withdrawal".');
}

async function getConfiguredNetworks() {
  const saved = await chrome.storage.local.get(['solana', 'evm', 'bitcoin', 'customNetworks']);
  const custom = Array.isArray(saved.customNetworks) ? saved.customNetworks : [];
  const networks = [
    { id: 'solana', label: 'Solana', address: saved.solana || '', kind: 'watch' },
    { id: 'evm', label: 'Ethereum / EVM', address: saved.evm || '', kind: 'watch' },
    { id: 'bitcoin', label: 'Bitcoin', address: saved.bitcoin || '', kind: 'watch' },
    ...custom.map(network => ({
      id: network.id || 'custom',
      label: network.label || 'Custom network',
      address: network.address || '',
      depositAddress: network.depositAddress || '',
      withdrawalAddress: network.withdrawalAddress || '',
      kind: network.kind || 'watch',
    }))
  ];

  return networks.filter(item => item.address || item.depositAddress || item.withdrawalAddress);
}

async function handleRequest(method, params = []) {
  if (method === 'tenebra_chainId') return TENEBRA_CHAIN_ID;
  if (method === 'tenebra_requestAccounts') return [await walletAddress()];
  if (method === 'tenebra_getAccounts') return walletFile ? [await walletAddress()] : [];
  if (method === 'tenebra_getSupportedChains') return Object.values(MULTICHAIN_REGISTRY).map(chain => ({ id: chain.id, label: chain.label, symbol: chain.symbol, requiredConfirmations: chain.requiredConfirmations, finality: chain.finality, supportsDeposit: chain.supportsDeposit, supportsWithdrawal: chain.supportsWithdrawal, adapter: chain.adapter }));
  if (method === 'tenebra_validateAddress') return validateAddress(params[0], params[1]);
  if (method === 'tenebra_createDepositRequest') return createDepositRequest(params[0], params[1]);
  if (method === 'tenebra_createWithdrawalRequest') return createWithdrawalRequest(params[0], params[1]);
  if (method === 'tenebra_createTransferRequest') return createTransferRequest(params[0], params[1]);
  if (method === 'tenebra_getNetworks') return getConfiguredNetworks();
  if (method === 'tenebra_addNetwork') {
    const next = Array.isArray(params[0]) ? params[0] : [params[0]];
    const saved = await chrome.storage.local.get('customNetworks');
    const current = Array.isArray(saved.customNetworks) ? saved.customNetworks : [];
    const merged = [...current, ...next.filter(Boolean)];
    await chrome.storage.local.set({ customNetworks: merged });
    return await getConfiguredNetworks();
  }
  if (method === 'tenebra_removeNetwork') {
    const id = String(params[0] || '');
    const saved = await chrome.storage.local.get('customNetworks');
    const current = Array.isArray(saved.customNetworks) ? saved.customNetworks : [];
    const filtered = current.filter(network => (network.id || network.label || '').toLowerCase() !== id.toLowerCase());
    await chrome.storage.local.set({ customNetworks: filtered });
    return await getConfiguredNetworks();
  }
  if (method === 'tenebra_signMessage') return signMessage(params[0]);
  if (method === 'tenebra_signDexCreatePool' || method === 'tenebra_signDexSwap' || method === 'tenebra_signDexRemoveLiquidity') return signDex(method, params[0]);
  if (method === 'tenebra_disconnect') { walletFile = null; walletPassword = null; return true; }
  throw new Error(`Metodă TENEBRA necunoscută: ${method}`);
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== 'TENEBRA_WALLET_REQUEST' || !sender.tab) return;
  handleRequest(message.method, message.params)
    .then(result => chrome.tabs.sendMessage(sender.tab.id, { type: 'TENEBRA_WALLET_RESPONSE', requestId: message.requestId, result }))
    .catch(error => chrome.tabs.sendMessage(sender.tab.id, { type: 'TENEBRA_WALLET_RESPONSE', requestId: message.requestId, error: error.message }));
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'TENEBRA_UNLOCK') return;
  try {
    walletFile = new Uint8Array(message.file);
    walletPassword = message.password;
    walletAddress().then(address => sendResponse({ ok: true, address })).catch(error => {
      walletFile = null; walletPassword = null; sendResponse({ ok: false, error: error.message });
    });
  } catch (error) { sendResponse({ ok: false, error: error.message }); }
  return true;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'TENEBRA_LOCK') return;
  walletFile = null;
  walletPassword = null;
  sendResponse({ ok: true });
});
