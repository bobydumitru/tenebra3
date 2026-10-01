(function (global) {
  const ADAPTERS = {
    solana: {
      id: 'solana',
      label: 'Solana',
      symbol: 'SOL',
      kind: 'adapter',
      status: 'ready-for-configuration',
      supportsDeposit: true,
      supportsWithdrawal: true,
      requiredConfirmations: 32,
      finality: 'confirmed',
      notes: 'Requires Solana RPC, vault configuration, and finalized confirmation verification.',
    },
    evm: {
      id: 'evm',
      label: 'Ethereum / EVM',
      symbol: 'ETH',
      kind: 'adapter',
      status: 'ready-for-configuration',
      supportsDeposit: true,
      supportsWithdrawal: true,
      requiredConfirmations: 12,
      finality: 'finalized',
      notes: 'Requires EVM RPC, gas policy, and finalization verification before crediting funds.',
    },
    bnb: {
      id: 'bnb', label: 'BNB Chain', symbol: 'BNB', kind: 'adapter', status: 'ready-for-configuration',
      supportsDeposit: true, supportsWithdrawal: true, requiredConfirmations: 15, finality: 'finalized',
      notes: 'EVM adapter with BNB gas policy and BNB Chain RPC.',
    },
    avalanche: {
      id: 'avalanche', label: 'Avalanche C-Chain', symbol: 'AVAX', kind: 'adapter', status: 'ready-for-configuration',
      supportsDeposit: true, supportsWithdrawal: true, requiredConfirmations: 12, finality: 'finalized',
      notes: 'EVM adapter for Avalanche C-Chain with AVAX gas policy.',
    },
    arbitrum: {
      id: 'arbitrum', label: 'Arbitrum One', symbol: 'ETH', kind: 'adapter', status: 'ready-for-configuration',
      supportsDeposit: true, supportsWithdrawal: true, requiredConfirmations: 20, finality: 'finalized',
      notes: 'EVM adapter for Arbitrum with ETH gas policy.',
    },
    ton: {
      id: 'ton', label: 'TON', symbol: 'TON', kind: 'adapter', status: 'ready-for-configuration',
      supportsDeposit: true, supportsWithdrawal: true, requiredConfirmations: 1, finality: 'confirmed',
      notes: 'Requires TON-specific address, cell serialization, wallet contract, and RPC.',
    },
    bitcoin: {
      id: 'bitcoin',
      label: 'Bitcoin',
      symbol: 'BTC',
      kind: 'adapter',
      status: 'ready-for-configuration',
      supportsDeposit: true,
      supportsWithdrawal: true,
      requiredConfirmations: 3,
      finality: 'confirmed',
      notes: 'Requires Bitcoin RPC, wallet policy, and confirmation depth checks.',
    },
  };

  function normalizeChainId(chainId) {
    return String(chainId || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'custom';
  }

  function getAdapter(chainId) {
    const key = normalizeChainId(chainId);
    return ADAPTERS[key] || null;
  }

  function buildAdapterSnapshot() {
    return Object.values(ADAPTERS).map(adapter => ({
      id: adapter.id,
      label: adapter.label,
      symbol: adapter.symbol,
      kind: adapter.kind,
      status: adapter.status,
      requiresConfiguration: true,
      supportsDeposit: adapter.supportsDeposit,
      supportsWithdrawal: adapter.supportsWithdrawal,
      requiredConfirmations: adapter.requiredConfirmations,
      finality: adapter.finality,
      notes: adapter.notes,
    }));
  }

  const api = {
    ADAPTERS,
    normalizeChainId,
    getAdapter,
    buildAdapterSnapshot,
  };

  global.tenebraAdapters = api;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
