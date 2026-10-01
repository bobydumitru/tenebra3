const queuedRandomFills = globalThis.__TENEBRA_WASM_RANDOM_QUEUE ?? new Map();
globalThis.__TENEBRA_WASM_RANDOM_QUEUE = queuedRandomFills;

function flushQueuedRandomFills(memory) {
  if (!memory || !queuedRandomFills.size) return;
  for (const [pointer, bytes] of [...queuedRandomFills]) {
    if (pointer < 0 || pointer + bytes.length > memory.buffer.byteLength) continue;
    new Uint8Array(memory.buffer, pointer, bytes.length).set(bytes);
    queuedRandomFills.delete(pointer);
  }
}
globalThis.__TENEBRA_WASM_FLUSH_RANDOMS = flushQueuedRandomFills;

let walletWasmInstance = globalThis.walletWasm;
if (!Object.getOwnPropertyDescriptor(globalThis, 'walletWasm')?.set) {
  Object.defineProperty(globalThis, 'walletWasm', {
    configurable: true,
    get: () => walletWasmInstance,
    set: value => {
      walletWasmInstance = value;
      globalThis.__TENEBRA_WASM_MEMORY = value?.memory;
      flushQueuedRandomFills(value?.memory);
    },
  });
}

export function random_fill(pointer, length) {
  const memory = globalThis.walletWasm?.memory ?? globalThis.__TENEBRA_WASM_MEMORY;
  if (!memory) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    queuedRandomFills.set(pointer, bytes);
    return;
  }
  crypto.getRandomValues(new Uint8Array(memory.buffer, pointer, length));
}
