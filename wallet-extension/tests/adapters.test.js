const test = require('node:test');
const assert = require('node:assert/strict');

const { getAdapter, buildAdapterSnapshot } = require('../adapters.js');

test('adapter registry exposes the supported chains', () => {
  const snapshot = buildAdapterSnapshot();
  const ids = snapshot.map(item => item.id).sort();
  assert.deepEqual(ids, ['arbitrum', 'avalanche', 'bitcoin', 'bnb', 'evm', 'solana', 'ton']);
  assert.equal(getAdapter('solana').label, 'Solana');
});

test('each adapter marks deposit and withdrawal support and finality', () => {
  const snapshot = buildAdapterSnapshot();
  const sol = snapshot.find(item => item.id === 'solana');
  const evm = snapshot.find(item => item.id === 'evm');
  const btc = snapshot.find(item => item.id === 'bitcoin');

  assert.equal(sol.supportsDeposit, true);
  assert.equal(evm.supportsWithdrawal, true);
  assert.equal(btc.requiredConfirmations, 3);
});
