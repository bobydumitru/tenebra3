const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeNetworkKey,
  normalizeCustomNetworks,
  buildNetworkRows,
  validateAddress,
} = require('../network-config.js');

function makeNetwork(label, address, depositAddress = '', withdrawalAddress = '') {
  return {
    id: normalizeNetworkKey(label),
    label,
    address,
    depositAddress,
    withdrawalAddress,
  };
}

test('normalizeNetworkKey converts arbitrary asset names into stable wallet keys', () => {
  assert.equal(normalizeNetworkKey('ADA'), 'ada');
  assert.equal(normalizeNetworkKey('  Solana  '), 'solana');
  assert.equal(normalizeNetworkKey('USDT / TRON'), 'usdt-tron');
  assert.equal(normalizeNetworkKey('!!!'), 'custom');
});

test('normalizeCustomNetworks keeps only valid custom entries and removes duplicates', () => {
  const list = [
    { id: 'ADA', label: 'ADA', address: 'addr_ada', depositAddress: 'deposit_ada', withdrawalAddress: 'withdraw_ada' },
    { id: 'ada', label: 'ADA', address: 'addr_ada_2', depositAddress: 'deposit_ada_2', withdrawalAddress: 'withdraw_ada_2' },
    { id: 'XRP', label: 'XRP', address: '' },
    { id: 'DOGE', label: 'DOGE', address: 'doge_addr', depositAddress: 'doge_deposit' },
  ];

  assert.deepEqual(normalizeCustomNetworks(list), [
    {
      id: 'ada',
      label: 'ADA',
      placeholder: 'Adresă publică',
      kind: 'watch',
      symbol: 'ADA',
      address: 'addr_ada',
      depositAddress: 'deposit_ada',
      withdrawalAddress: 'withdraw_ada',
      supportsDeposit: true,
      supportsWithdrawal: true,
    },
    {
      id: 'doge',
      label: 'DOGE',
      placeholder: 'Adresă publică',
      kind: 'watch',
      symbol: 'DOGE',
      address: 'doge_addr',
      depositAddress: 'doge_deposit',
      withdrawalAddress: '',
      supportsDeposit: true,
      supportsWithdrawal: true,
    },
  ]);
});

test('buildNetworkRows merges default and custom wallet networks', () => {
  const rows = buildNetworkRows({
    solana: 'sol_addr',
    customNetworks: [
      { id: 'ADA', label: 'ADA', address: 'ada_addr', depositAddress: 'ada_dep', withdrawalAddress: 'ada_withdraw' },
      { id: 'XRP', label: 'XRP', address: 'xrp_addr' },
    ],
  });

  const ids = rows.map(row => row.id);
  assert.ok(ids.includes('solana'));
  assert.ok(ids.includes('ada'));
  assert.ok(ids.includes('xrp'));
  assert.equal(rows.find(row => row.id === 'solana').address, 'sol_addr');
  assert.equal(rows.find(row => row.id === 'ada').address, 'ada_addr');
  assert.equal(rows.find(row => row.id === 'ada').depositAddress, 'ada_dep');
  assert.equal(rows.find(row => row.id === 'ada').withdrawalAddress, 'ada_withdraw');
});

test('custom network list can be serialized for wallet API consumers', () => {
  const list = [
    makeNetwork('ADA', 'ada_addr', 'ada_deposit', 'ada_withdraw'),
    makeNetwork('XRP', 'xrp_addr'),
    makeNetwork('ADA', 'ada_addr_dup', 'ada_deposit_dup', 'ada_withdraw_dup'),
  ];

  const normalized = normalizeCustomNetworks(list);
  assert.equal(normalized.length, 2);
  assert.equal(normalized[0].label, 'ADA');
  assert.equal(normalized[0].depositAddress, 'ada_deposit');
  assert.equal(normalized[1].withdrawalAddress, '');
});

test('supported network registry validates real chain addresses', () => {
  const sol = validateAddress('solana', '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4');
  const evm = validateAddress('evm', '0x1234567890abcdef1234567890abcdef12345678');
  const btc = validateAddress('bitcoin', 'bc1qw508d6qejxtdg4y9r3zarvary0c5xw7kg3g4ty');
  const bad = validateAddress('solana', 'not-a-valid-solana-address');

  assert.equal(sol.valid, true);
  assert.equal(evm.valid, true);
  assert.equal(btc.valid, true);
  assert.equal(bad.valid, false);
});
