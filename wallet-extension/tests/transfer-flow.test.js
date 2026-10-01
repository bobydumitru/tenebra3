const test = require('node:test');
const assert = require('node:assert/strict');

const { createTransferRequest } = require('../multichain.js');

test('transfer request builder creates valid deposit and withdrawal flows for supported chains', () => {
  const deposit = createTransferRequest('solana', {
    type: 'deposit',
    amount: 12.5,
    address: '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4',
    vault: 'vault-solana'
  });

  const withdrawal = createTransferRequest('evm', {
    type: 'withdrawal',
    amount: 2.25,
    recipient: '0x1234567890abcdef1234567890abcdef12345678',
    source: 'wallet'
  });

  assert.equal(deposit.type, 'deposit');
  assert.equal(withdrawal.type, 'withdrawal');
  assert.equal(deposit.requiredConfirmations, 32);
  assert.equal(withdrawal.finality, 'finalized');
  assert.equal(deposit.adapter, 'solana');
  assert.equal(withdrawal.status, 'pending-verification');
});

test('transfer request builder rejects unsupported chains and invalid amounts', () => {
  assert.throws(() => createTransferRequest('custom', { type: 'withdrawal', amount: 1, recipient: 'abc' }), /nu este suportată|invalid/i);
  assert.throws(() => createTransferRequest('solana', { type: 'withdrawal', amount: -1, recipient: '5T7sE4LVMh8jrcYkTn6vY8n4h8gqZKxR4Q2q3d4L5YV4' }), /invalid/i);
});
