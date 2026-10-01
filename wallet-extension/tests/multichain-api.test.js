const test = require('node:test');
const assert = require('node:assert/strict');

const { validateAddress, createDepositRequest, createWithdrawalRequest, buildRegistrySnapshot } = require('../multichain.js');

test('adapter exposes registry through the multichain model', () => {
  const registry = buildRegistrySnapshot();
  assert.equal(registry.length, 7);
  assert.ok(registry.some(chain => chain.id === 'solana'));
  assert.ok(registry.some(chain => chain.id === 'evm'));
  assert.ok(registry.some(chain => chain.id === 'bitcoin'));
  assert.ok(registry.some(chain => chain.id === 'bnb'));
  assert.ok(registry.some(chain => chain.id === 'avalanche'));
  assert.ok(registry.some(chain => chain.id === 'arbitrum'));
  assert.ok(registry.some(chain => chain.id === 'ton'));
});

test('address validation works across the real supported network set', () => {
  assert.equal(validateAddress('solana', '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4').valid, true);
  assert.equal(validateAddress('evm', '0x1234567890abcdef1234567890abcdef12345678').valid, true);
  assert.equal(validateAddress('bitcoin', 'bc1qw508d6qejxtdg4y9r3zarvary0c5xw7kg3g4ty').valid, true);
  assert.equal(validateAddress('evm', 'bad-address').valid, false);
});

test('deposit and withdrawal requests carry chain finality metadata', () => {
  const deposit = createDepositRequest('solana', { amount: 10, address: '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4', vault: 'vault-solana' });
  const withdrawal = createWithdrawalRequest('evm', { amount: 2.5, recipient: '0x1234567890abcdef1234567890abcdef12345678' });

  assert.equal(deposit.chainId, 'solana');
  assert.equal(deposit.requiredConfirmations, 32);
  assert.equal(withdrawal.chainId, 'evm');
  assert.equal(withdrawal.finality, 'finalized');
});
