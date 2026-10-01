(function (global) {
  const DEFAULT_NETWORKS = [
    {
      id: 'solana',
      label: 'Solana',
      symbol: 'SOL',
      placeholder: 'Address Solana',
      kind: 'chain',
      addressPattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
      supportsDeposit: true,
      supportsWithdrawal: true,
    },
    {
      id: 'evm',
      label: 'Ethereum / EVM',
      symbol: 'ETH',
      placeholder: '0x...',
      kind: 'chain',
      addressPattern: /^0x[a-fA-F0-9]{40}$/,
      supportsDeposit: true,
      supportsWithdrawal: true,
    },
    { id: 'bnb', label: 'BNB Chain', symbol: 'BNB', placeholder: '0x...', kind: 'chain', addressPattern: /^0x[a-fA-F0-9]{40}$/, supportsDeposit: true, supportsWithdrawal: true },
    { id: 'avalanche', label: 'Avalanche C-Chain', symbol: 'AVAX', placeholder: '0x...', kind: 'chain', addressPattern: /^0x[a-fA-F0-9]{40}$/, supportsDeposit: true, supportsWithdrawal: true },
    { id: 'arbitrum', label: 'Arbitrum One', symbol: 'ETH', placeholder: '0x...', kind: 'chain', addressPattern: /^0x[a-fA-F0-9]{40}$/, supportsDeposit: true, supportsWithdrawal: true },
    { id: 'ton', label: 'TON', symbol: 'TON', placeholder: 'TON address', kind: 'chain', addressPattern: /^[A-Za-z0-9_-]{40,70}$/, supportsDeposit: true, supportsWithdrawal: true },
    {
      id: 'bitcoin',
      label: 'Bitcoin',
      symbol: 'BTC',
      placeholder: 'bc1... / 1... / 3...',
      kind: 'chain',
      addressPattern: /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
      supportsDeposit: true,
      supportsWithdrawal: true,
    },
  ];

  const CHAIN_REGISTRY = DEFAULT_NETWORKS.map(network => ({
    ...network,
    id: normalizeNetworkKey(network.id),
  }));

  function normalizeNetworkKey(value) {
    const cleaned = String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 32);

    return cleaned || 'custom';
  }

  function titleCase(value) {
    return String(value || '')
      .trim()
      .replace(/[-_]+/g, ' ')
      .replace(/\b\w/g, char => char.toUpperCase());
  }

  function toNetworkEntry(item) {
    if (!item) return null;
    const id = normalizeNetworkKey(item.id || item.name || item.label || 'custom');
    const label = String(item.label || item.name || titleCase(id) || 'Custom network').trim();
    const address = String(item.address || '').trim();
    const depositAddress = String(item.depositAddress || '').trim();
    const withdrawalAddress = String(item.withdrawalAddress || item.withdrawAddress || '').trim();
    return {
      id,
      label,
      placeholder: item.placeholder || 'Adresă publică',
      kind: item.kind || 'watch',
      symbol: item.symbol || label.toUpperCase(),
      address,
      depositAddress,
      withdrawalAddress,
      supportsDeposit: item.supportsDeposit !== undefined ? Boolean(item.supportsDeposit) : true,
      supportsWithdrawal: item.supportsWithdrawal !== undefined ? Boolean(item.supportsWithdrawal) : true,
    };
  }

  function normalizeCustomNetworks(list) {
    if (!Array.isArray(list)) return [];
    const seen = new Set();
    return list
      .map(toNetworkEntry)
      .filter(Boolean)
      .filter(entry => entry.address || entry.depositAddress || entry.withdrawalAddress)
      .filter(entry => {
        if (seen.has(entry.id)) return false;
        seen.add(entry.id);
        return true;
      });
  }

  function getSupportedNetworkById(networkId) {
    const key = normalizeNetworkKey(networkId);
    return CHAIN_REGISTRY.find(network => network.id === key) || null;
  }

  function validateAddress(networkId, value) {
    const network = getSupportedNetworkById(networkId);
    const address = String(value || '').trim();

    if (!network) {
      return { valid: false, reason: 'Rețeaua nu este suportată.', networkId: normalizeNetworkKey(networkId) };
    }

    if (!address) {
      return { valid: false, reason: 'Adresa este goală.', networkId: network.id };
    }

    const matches = network.addressPattern && network.addressPattern.test(address);
    if (!matches) {
      return { valid: false, reason: `Adresă invalidă pentru ${network.label}.`, networkId: network.id };
    }

    return { valid: true, reason: 'Adresă validă.', networkId: network.id, normalized: address };
  }

  function buildNetworkRows(saved = {}) {
    const customNetworks = normalizeCustomNetworks(saved.customNetworks || []);
    const rows = [
      ...CHAIN_REGISTRY.map(network => ({
        ...network,
        address: String(saved[network.id] || '').trim(),
        depositAddress: String(saved[`${network.id}-deposit`] || '').trim(),
        withdrawalAddress: String(saved[`${network.id}-withdrawal`] || '').trim(),
      })),
      ...customNetworks.map(network => ({
        id: network.id,
        label: network.label,
        placeholder: network.placeholder,
        kind: network.kind,
        symbol: network.symbol,
        address: network.address,
        depositAddress: network.depositAddress,
        withdrawalAddress: network.withdrawalAddress,
        supportsDeposit: network.supportsDeposit,
        supportsWithdrawal: network.supportsWithdrawal,
      })),
    ];

    const unique = new Map();
    for (const row of rows) {
      if (!row || !row.id) continue;
      if (!unique.has(row.id)) {
        unique.set(row.id, row);
      }
    }
    return Array.from(unique.values());
  }

  function serializeNetworkState(rows) {
    return Array.isArray(rows)
      ? rows.map(row => ({
          id: row.id,
          label: row.label,
          symbol: row.symbol,
          address: row.address || '',
          depositAddress: row.depositAddress || '',
          withdrawalAddress: row.withdrawalAddress || '',
          kind: row.kind || 'chain',
          supportsDeposit: row.supportsDeposit !== false,
          supportsWithdrawal: row.supportsWithdrawal !== false,
        }))
      : [];
  }

  const api = {
    DEFAULT_NETWORKS,
    CHAIN_REGISTRY,
    normalizeNetworkKey,
    titleCase,
    toNetworkEntry,
    normalizeCustomNetworks,
    buildNetworkRows,
    serializeNetworkState,
    getSupportedNetworkById,
    validateAddress,
  };

  global.tenebraNetworkConfig = api;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
