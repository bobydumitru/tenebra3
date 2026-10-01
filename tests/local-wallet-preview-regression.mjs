import assert from 'node:assert/strict';
import fs from 'node:fs';

const tenebraWalletHtml = fs.readFileSync('tenebra-wallet.html', 'utf8');
assert.match(
  tenebraWalletHtml,
  /isLocalPreview\s*\|\||location\.hostname === 'localhost'|location\.protocol === 'file:'/, 
  'Preview page must explicitly allow local or VS preview origins before redirecting.'
);
assert.doesNotMatch(
  tenebraWalletHtml,
  /if\s*\(\s*window\.location\.origin\s*!==\s*'https:\/\/tenebra-network\.com'\s*\)/,
  'Preview page must not force an unconditional origin redirect.'
);

const webWalletHtml = fs.readFileSync('web-wallet.html', 'utf8');
assert.match(
  webWalletHtml,
  /function\s+resolveApiBase\s*\(|function\s+apiFetch\s*\(/,
  'Wallet page must resolve API calls to the public API when opened outside the hosted website.'
);
assert.doesNotMatch(
  webWalletHtml,
  /fetch\(\s*['"]\/api\/submit['"]\s*\)/,
  'Transfer submit must not use a plain relative /api/submit fetch from local preview sessions.'
);
assert.match(
  webWalletHtml,
  /apiFetch\(\s*['"]\/api\/submit['"]\s*,\s*\{\s*method:\s*'POST'|apiFetch\(\s*['"]\/api\/submit['"]\s*,\s*\{\s*method:\s*"POST"/,
  'Transfer submit must use the API resolver so the browser reaches the real public API endpoint.'
);
