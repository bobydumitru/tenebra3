(function (global) {
  const CHAIN_REGISTRY = {
    solana: {
      id: 'solana',
      label: 'Solana',
      symbol: 'SOL',
      addressPattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
      requiredConfirmations: 32,
      finality: 'confirmed',
      supportsDeposit: true,
      supportsWithdrawal: true,
      adapter: 'solana',
    },
    evm: {
      id: 'evm',
      label: 'Ethereum / EVM',
      symbol: 'ETH',
      addressPattern: /^0x[a-fA-F0-9]{40}$/,
      requiredConfirmations: 12,
      finality: 'finalized',
      supportsDeposit: true,
      supportsWithdrawal: true,
      adapter: 'evm',
    },
    bnb: {
      id: 'bnb', label: 'BNB Chain', symbol: 'BNB', addressPattern: /^0x[a-fA-F0-9]{40}$/,
      requiredConfirmations: 15, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'bnb',
    },
    avalanche: {
      id: 'avalanche', label: 'Avalanche C-Chain', symbol: 'AVAX', addressPattern: /^0x[a-fA-F0-9]{40}$/,
      requiredConfirmations: 12, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'avalanche',
    },
    arbitrum: {
      id: 'arbitrum', label: 'Arbitrum One', symbol: 'ETH', addressPattern: /^0x[a-fA-F0-9]{40}$/,
      requiredConfirmations: 20, finality: 'finalized', supportsDeposit: true, supportsWithdrawal: true, adapter: 'arbitrum',
    },
    ton: {
      id: 'ton', label: 'TON', symbol: 'TON', addressPattern: /^[A-Za-z0-9_-]{40,70}$/,
      requiredConfirmations: 1, finality: 'confirmed', supportsDeposit: true, supportsWithdrawal: true, adapter: 'ton',
    },
    bitcoin: {
      id: 'bitcoin',
      label: 'Bitcoin',
      symbol: 'BTC',
      addressPattern: /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
      requiredConfirmations: 3,
      finality: 'confirmed',
      supportsDeposit: true,
      supportsWithdrawal: true,
      adapter: 'bitcoin',
    },
  };

  function normalizeChainId(chainId) {
    return String(chainId || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'custom';
  }

  function getChain(chainId) {
    const key = normalizeChainId(chainId);
    return CHAIN_REGISTRY[key] || null;
  }

  function validateAddress(chainId, value) {
    const chain = getChain(chainId);
    const address = String(value || '').trim();

    if (!chain) {
      return { valid: false, chainId: normalizeChainId(chainId), reason: 'Rețeaua nu este suportată.' };
    }

    if (!address) {
      return { valid: false, chainId: chain.id, reason: 'Adresa este goală.' };
    }

    const matches = chain.addressPattern && chain.addressPattern.test(address);
    if (!matches) {
      return { valid: false, chainId: chain.id, reason: `Adresă invalidă pentru ${chain.label}.` };
    }

    return { valid: true, chainId: chain.id, normalized: address, reason: 'Adresă validă.' };
  }

  function createDepositRequest(chainId, input) {
    const chain = getChain(chainId);
    if (!chain) throw new Error('Rețeaua nu este suportată pentru depozit.');

    const amount = Number(input && input.amount);
    const address = validateAddress(chainId, input && input.address);
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
    const chain = getChain(chainId);
    if (!chain) throw new Error('Rețeaua nu este suportată pentru retragere.');

    const amount = Number(input && input.amount);
    const recipient = validateAddress(chainId, input && input.recipient);
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
    const mode = String(input && input.type || '').trim().toLowerCase();
    if (mode === 'deposit') return createDepositRequest(chainId, input);
    if (mode === 'withdrawal') return createWithdrawalRequest(chainId, input);

    const chain = getChain(chainId);
    if (!chain) throw new Error('Rețeaua nu este suportată pentru transfer.');

    throw new Error('Tipul de transfer este invalid. Folosește "deposit" sau "withdrawal".');
  }

  function buildRegistrySnapshot() {
    return Object.values(CHAIN_REGISTRY).map(chain => ({
      id: chain.id,
      label: chain.label,
      symbol: chain.symbol,
      requiredConfirmations: chain.requiredConfirmations,
      finality: chain.finality,
      supportsDeposit: chain.supportsDeposit,
      supportsWithdrawal: chain.supportsWithdrawal,
      adapter: chain.adapter,
    }));
  }

  const api = {
    CHAIN_REGISTRY,
    normalizeChainId,
    getChain,
    validateAddress,
    createDepositRequest,
    createWithdrawalRequest,
    createTransferRequest,
    buildRegistrySnapshot,
  };

  global.tenebraMultiChain = api;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
