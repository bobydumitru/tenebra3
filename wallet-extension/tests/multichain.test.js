const test = require('node:test');
const assert = require('node:assert/strict');

const {
  getChain,
  validateAddress,
  createDepositRequest,
  createWithdrawalRequest,
  buildRegistrySnapshot,
} = require('../multichain.js');

test('multichain registry exposes all three supported chains', () => {
  const list = buildRegistrySnapshot();
  const ids = list.map(chain => chain.id);
  assert.deepEqual(ids.sort(), ['arbitrum', 'avalanche', 'bitcoin', 'bnb', 'evm', 'solana', 'ton']);
  assert.equal(getChain('solana').adapter, 'solana');
});

test('supported chain addresses validate with correct rules', () => {
  assert.equal(validateAddress('solana', '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4').valid, true);
  assert.equal(validateAddress('evm', '0x1234567890abcdef1234567890abcdef12345678').valid, true);
  assert.equal(validateAddress('bitcoin', 'bc1qw508d6qejxtdg4y9r3zarvary0c5xw7kg3g4ty').valid, true);
  assert.equal(validateAddress('solana', 'not-valid').valid, false);
});

test('deposit and withdrawal requests are created with finality metadata', () => {
  const deposit = createDepositRequest('solana', { amount: 10, address: '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4', vault: 'vault-solana' });
  const withdrawal = createWithdrawalRequest('evm', { amount: 2.5, recipient: '0x1234567890abcdef1234567890abcdef12345678', source: 'wallet' });

  assert.equal(deposit.type, 'deposit');
  assert.equal(deposit.requiredConfirmations, 32);
  assert.equal(withdrawal.type, 'withdrawal');
  assert.equal(withdrawal.finality, 'finalized');
});
