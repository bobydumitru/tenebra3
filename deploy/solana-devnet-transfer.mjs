import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Connection, Keypair, LAMPORTS_PER_SOL, SystemProgram, Transaction, sendAndConfirmTransaction } = require('@solana/web3.js');

const rpcUrls = (process.env.TENEBRA_SOLANA_TESTNET_RPC_URLS || process.env.TENEBRA_SOLANA_TESTNET_RPC_URL || 'https://api.testnet.solana.com')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);
let connection = new Connection(rpcUrls[0], 'confirmed');
const sender = Keypair.generate();
const recipient = Keypair.generate();
const airdropAmount = 0.1 * LAMPORTS_PER_SOL;
const transferAmount = 100_000;

async function requestConfirmedAirdrop() {
  let lastError;
  for (const rpcUrl of rpcUrls) {
    connection = new Connection(rpcUrl, 'confirmed');
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        const signature = await connection.requestAirdrop(sender.publicKey, airdropAmount);
        await connection.confirmTransaction(signature, 'confirmed');
        console.log(`devnet_rpc=${rpcUrl}`);
        return signature;
      } catch (error) {
        lastError = error;
        if (attempt < 3) await new Promise(resolve => setTimeout(resolve, attempt * 1500));
      }
    }
  }
  throw lastError;
}

console.log(`sender=${sender.publicKey.toBase58()}`);
console.log(`recipient=${recipient.publicKey.toBase58()}`);
console.log(`requesting_airdrop_lamports=${airdropAmount}`);

const airdropSignature = await requestConfirmedAirdrop();

const balance = await connection.getBalance(sender.publicKey, 'confirmed');
if (balance < transferAmount) throw new Error(`devnet faucet balance too low: ${balance}`);

const transaction = new Transaction().add(SystemProgram.transfer({
  fromPubkey: sender.publicKey,
  toPubkey: recipient.publicKey,
  lamports: transferAmount,
}));
const signature = await sendAndConfirmTransaction(connection, transaction, [sender], { commitment: 'confirmed' });
const recipientBalance = await connection.getBalance(recipient.publicKey, 'confirmed');

console.log(`airdrop_signature=${airdropSignature}`);
console.log(`transfer_signature=${signature}`);
console.log(`recipient_balance_lamports=${recipientBalance}`);
console.log(`explorer=https://explorer.solana.com/tx/${signature}?cluster=devnet`);
