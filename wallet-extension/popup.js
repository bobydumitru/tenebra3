const status = document.getElementById('status');
const address = document.getElementById('address');
const networks = ['solana', 'evm', 'bitcoin'];

function showStatus(text, error = false) {
  status.textContent = text;
  status.className = error ? 'status error' : 'status';
}

async function loadCustomNetworks() {
  const saved = await chrome.storage.local.get('customNetworks');
  return Array.isArray(saved.customNetworks) ? saved.customNetworks : [];
}

async function renderCustomNetworks() {
  const customNetworks = await loadCustomNetworks();
  const info = customNetworks.length
    ? customNetworks.map(network => {
        const deposit = network.depositAddress ? ` | depunere: ${network.depositAddress}` : '';
        const withdrawal = network.withdrawalAddress ? ` | retragere: ${network.withdrawalAddress}` : '';
        return `${network.label}: ${network.address || 'nespecificată'}${deposit}${withdrawal}`;
      }).join('\n')
    : 'Nicio monedă personalizată salvată.';
  document.getElementById('custom-network-watch').textContent = info;
}

async function renderSupportedNetworks() {
  const saved = await chrome.storage.local.get([...networks, 'customNetworks']);
  const rows = window.tenebraNetworkConfig.buildNetworkRows(saved);
  const registryText = rows.length
    ? rows.map(network => `${network.label}: ${network.address || 'nespecificată'}${network.depositAddress ? ` / depunere: ${network.depositAddress}` : ''}${network.withdrawalAddress ? ` / retragere: ${network.withdrawalAddress}` : ''}`).join('\n')
    : 'Nicio rețea suportată salvată.';
  document.getElementById('supported-network-watch').textContent = registryText;
}

function validateSupportedAddress(networkId, value) {
  const result = window.tenebraNetworkConfig.validateAddress(networkId, value);
  if (!result.valid) throw new Error(result.reason);
  return result.normalized;
}

document.getElementById('unlock').addEventListener('click', async () => {
  const file = document.getElementById('wallet-file').files[0];
  const password = document.getElementById('password').value;
  if (!file || !password) return showStatus('Selectează fișierul și parola.', true);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const result = await chrome.runtime.sendMessage({ type: 'TENEBRA_UNLOCK', file: Array.from(bytes), password });
  if (!result?.ok) return showStatus(result?.error || 'Wallet invalid.', true);
  address.textContent = result.address;
  showStatus('Wallet deblocat pentru această sesiune.');
});

document.getElementById('lock').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'TENEBRA_LOCK' });
  address.textContent = '';
  showStatus('Wallet blocat.');
});

async function refreshNetworks() {
  const saved = await chrome.storage.local.get([...networks, 'customNetworks']);
  for (const network of networks) {
    const value = saved[network] || '';
    document.getElementById(`${network}-address`).value = value;
    document.getElementById(`${network}-watch`).textContent = value ? `Observare: ${value}` : 'Nicio adresă salvată.';
  }

  await renderSupportedNetworks();
  await renderCustomNetworks();
}

for (const network of networks) {
  document.getElementById(`save-${network}`).addEventListener('click', async () => {
    const value = document.getElementById(`${network}-address`).value.trim();
    if (!value) return showStatus('Introdu o adresă publică.', true);
    try {
      validateSupportedAddress(network, value);
      await chrome.storage.local.set({ [network]: value });
      document.getElementById(`${network}-watch`).textContent = `Observare: ${value}`;
      showStatus(`${network} adăugat ca adresă publică validată.`);
      await renderSupportedNetworks();
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

document.getElementById('save-supported-network').addEventListener('click', async () => {
  const networkId = document.getElementById('supported-network-select').value;
  const value = document.getElementById('supported-network-address').value.trim();
  const deposit = document.getElementById('supported-network-deposit').value.trim();
  const withdraw = document.getElementById('supported-network-withdraw').value.trim();

  if (!value) return showStatus('Introdu adresa publică pentru rețeaua selectată.', true);

  try {
    const normalized = validateSupportedAddress(networkId, value);
    const payload = {
      id: networkId,
      label: window.tenebraNetworkConfig.getSupportedNetworkById(networkId)?.label || networkId,
      symbol: window.tenebraNetworkConfig.getSupportedNetworkById(networkId)?.symbol || networkId.toUpperCase(),
      address: normalized,
      depositAddress: deposit,
      withdrawalAddress: withdraw,
      supportsDeposit: true,
      supportsWithdrawal: true,
    };

    await chrome.storage.local.set({ [networkId]: normalized, [`${networkId}-deposit`]: deposit, [`${networkId}-withdrawal`]: withdraw });
    await renderSupportedNetworks();
    document.getElementById('supported-network-address').value = '';
    document.getElementById('supported-network-deposit').value = '';
    document.getElementById('supported-network-withdraw').value = '';
    showStatus(`${payload.label} salvată ca rețea suportată validată.`);
  } catch (error) {
    showStatus(error.message, true);
  }
});

document.getElementById('save-custom-network').addEventListener('click', async () => {
  const name = document.getElementById('custom-network-name').value.trim();
  const value = document.getElementById('custom-network-address').value.trim();
  const deposit = document.getElementById('custom-network-deposit').value.trim();
  const withdraw = document.getElementById('custom-network-withdraw').value.trim();
  if (!name || !value) return showStatus('Introdu numele monedei și adresa publică.', true);

  const config = await loadCustomNetworks();
  const key = window.tenebraNetworkConfig.normalizeNetworkKey(name);
  const next = window.tenebraNetworkConfig.normalizeCustomNetworks([
    ...config,
    {
      id: key,
      label: name.toUpperCase(),
      address: value,
      depositAddress: deposit,
      withdrawalAddress: withdraw,
    }
  ]);

  await chrome.storage.local.set({ customNetworks: next });
  document.getElementById('custom-network-name').value = '';
  document.getElementById('custom-network-address').value = '';
  document.getElementById('custom-network-deposit').value = '';
  document.getElementById('custom-network-withdraw').value = '';
  await renderSupportedNetworks();
  await renderCustomNetworks();
  showStatus(`${name.toUpperCase()} adăugată ca monedă personalizată.`);
});

refreshNetworks();
