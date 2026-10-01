import assert from 'node:assert/strict';
import fs from 'node:fs';
import init from '../assets/wallet-wasm/tenebra_wallet_wasm.js';
const wasmBytes=fs.readFileSync('assets/wallet-wasm/tenebra_wallet_wasm_bg.wasm');
const wasmModule=new WebAssembly.Module(wasmBytes);
const wasmImports=WebAssembly.Module.imports(wasmModule);
assert.ok(wasmImports.some(item=>item.module==='./env.js'&&item.name==='unix_time'));
assert.ok(!wasmImports.some(item=>item.module==='env'));
const wasm=await init({module_or_path:wasmModule});
globalThis.walletWasm=wasm;
const root='target/wallet-regression/';
function call(fn,inputs,size){const pointers=[];const alloc=bytes=>{const n=typeof bytes==='number'?bytes:bytes.length;const ptr=wasm.wallet_alloc(n);pointers.push([ptr,n]);if(typeof bytes!=='number')new Uint8Array(wasm.memory.buffer,ptr,n).set(bytes);return ptr;};try{const args=inputs.map(value=>typeof value==='bigint'||typeof value==='number'?value:alloc(value));const out=alloc(size);const count=wasm[fn](...args,out);return {count,bytes:new Uint8Array(wasm.memory.buffer.slice(out,out+size))};}finally{for(const [ptr,n] of pointers){new Uint8Array(wasm.memory.buffer,ptr,n).fill(0);wasm.wallet_free(ptr,n);}}}
const sender=new Uint8Array(32).fill(203),recipient=new Uint8Array(32).fill(204);
const address=call('wallet_address',[recipient],160);const text=new TextDecoder().decode(address.bytes.subarray(0,address.count));assert.match(text,/^tsc1_[0-9a-f]{136}$/);
const phase=process.argv[2]||'sign';
if(phase==='recovery'){
 const encoded=call('wallet_seed_to_mnemonic',[sender],512);assert.ok(encoded.count>0);const phrase=new TextDecoder().decode(encoded.bytes.subarray(0,encoded.count));assert.equal(phrase.split(' ').length,24);
 const restored=call('wallet_mnemonic_to_seed',[new TextEncoder().encode(phrase),phrase.length],32);assert.equal(restored.count,32);assert.deepEqual(restored.bytes,sender);
 const originalAddress=call('wallet_address',[sender],160),restoredAddress=call('wallet_address',[restored.bytes],160);assert.equal(new TextDecoder().decode(restoredAddress.bytes.subarray(0,restoredAddress.count)),new TextDecoder().decode(originalAddress.bytes.subarray(0,originalAddress.count)));
 const invalidLength=new TextEncoder().encode('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon');assert.equal(call('wallet_mnemonic_to_seed',[invalidLength,invalidLength.length],32).count,0);
 const invalidChecksum=new TextEncoder().encode(Array(24).fill('abandon').join(' '));assert.equal(call('wallet_mnemonic_to_seed',[invalidChecksum,invalidChecksum.length],32).count,0);
 console.log('PASS: 24-word recovery preserves all 32 seed bytes and the exact address; invalid phrase rejected.');
}
else if(phase==='migration'){
 const password=new TextEncoder().encode('test-password-only');const imported=call('wallet_native_file_seed',[fs.readFileSync(root+'synthetic.tsc1'),password,password.length],32);assert.equal(imported.count,32);assert.deepEqual(imported.bytes,sender);
 const encoded=call('wallet_seed_to_mnemonic',[imported.bytes],512);assert.ok(encoded.count>0);const phrase=new TextDecoder().decode(encoded.bytes.subarray(0,encoded.count));assert.equal(phrase.split(' ').length,24);const restored=call('wallet_mnemonic_to_seed',[new TextEncoder().encode(phrase),phrase.length],32);assert.equal(restored.count,32);assert.deepEqual(restored.bytes,imported.bytes);
 const sourceAddress=call('wallet_address',[imported.bytes],160),restoredAddress=call('wallet_address',[restored.bytes],160);assert.equal(new TextDecoder().decode(restoredAddress.bytes.subarray(0,restoredAddress.count)),new TextDecoder().decode(sourceAddress.bytes.subarray(0,sourceAddress.count)));
 console.log('PASS: existing encrypted .tsc1 seed restores from 24 words to the exact same address.');
}
else if(phase==='sign'){
 const before=fs.readFileSync(root+'before.bin');
 const password=new TextEncoder().encode('test-password-only');
 const imported=call('wallet_native_file_seed',[fs.readFileSync(root+'synthetic.tsc1'),password,password.length],32);assert.equal(imported.count,32);assert.deepEqual(imported.bytes,sender);
 const legacyPhrase=call('wallet_seed_to_mnemonic',[imported.bytes],512);assert.ok(legacyPhrase.count>0);const legacyWords=new TextDecoder().decode(legacyPhrase.bytes.subarray(0,legacyPhrase.count));const restoredLegacy=call('wallet_mnemonic_to_seed',[new TextEncoder().encode(legacyWords),legacyWords.length],32);assert.equal(restoredLegacy.count,32);assert.deepEqual(restoredLegacy.bytes,imported.bytes);const importedAddress=call('wallet_address',[imported.bytes],160),restoredLegacyAddress=call('wallet_address',[restoredLegacy.bytes],160);assert.equal(new TextDecoder().decode(restoredLegacyAddress.bytes.subarray(0,restoredLegacyAddress.count)),new TextDecoder().decode(importedAddress.bytes.subarray(0,importedAddress.count)));
 const wrong=new TextEncoder().encode('incorrect');assert.equal(call('wallet_native_file_seed',[fs.readFileSync(root+'synthetic.tsc1'),wrong,wrong.length],32).count,0);
 const balance=call('wallet_seed_balance',[sender,before,before.length],8);assert.equal(balance.count,1);assert.ok(new DataView(balance.bytes.buffer).getBigUint64(0,true)>110n);
 const history=call('wallet_seed_history_v2',[sender,before,before.length],4+4096*64);assert.equal(history.count,0);
 const bad=new Uint8Array([1,0,0,0,255]);assert.equal(call('wallet_seed_balance',[sender,bad,bad.length],8).count,0);assert.equal(call('wallet_seed_history_v2',[sender,bad,bad.length],4+4096*64).count>>>0,4294967295);
 const emptyChain=new Uint8Array(4),assetName=new TextEncoder().encode('ABI test'),assetSymbol=new TextEncoder().encode('ABIT');assert.equal(call('wallet_seed_sign_asset_create',[sender,emptyChain,emptyChain.length,assetName,assetName.length,assetSymbol,assetSymbol.length,9,1000000000n,1000000000n],512*1024).count,0,'asset signing with no mature fee UTXO returns normally');
 const destination=new TextEncoder().encode(text),assetId=new Uint8Array(32).fill(7);const assetTransfer=call('wallet_seed_sign_asset_transfer',[sender,before,before.length,assetId,destination,destination.length,1n],8192);assert.equal(assetTransfer.count,0,'WASM rejects a transfer for an asset absent from the chain');
 const signed=call('wallet_seed_sign_transfer',[sender,before,before.length,destination,destination.length,100n,10n],512*1024);assert.ok(signed.count>0,'WASM signs a transfer with mature synthetic funds');fs.writeFileSync(root+'signed.bin',signed.bytes.subarray(0,signed.count));
 console.log('PASS: native import and same-address recovery, password rejection, balance, empty history, malformed chain rejection, real WASM transfer signing.');
}else if(phase==='asset-fee-history'){
 const blocks=fs.readFileSync(root+'asset-fee-history.bin');
 const expected=JSON.parse(fs.readFileSync(root+'asset-fee-history.json'));
 const senderBalance=call('wallet_seed_balance',[sender,blocks,blocks.length],8);assert.equal(senderBalance.count,1);assert.equal(new DataView(senderBalance.bytes.buffer).getBigUint64(0,true).toString(),expected.sender,'WASM balance must include sender change from the asset creation fee');
 const recipientBalance=call('wallet_seed_balance',[recipient,blocks,blocks.length],8);assert.equal(recipientBalance.count,1);assert.equal(new DataView(recipientBalance.bytes.buffer).getBigUint64(0,true).toString(),expected.recipient);
 const senderHistory=call('wallet_seed_history_v2',[sender,blocks,blocks.length],4+4096*64);assert.equal(senderHistory.count,2,'funding receive and asset creation fee must both appear in sender history');
 const senderView=new DataView(senderHistory.bytes.buffer);assert.equal(senderView.getBigUint64(4+16,true),10000000000n,'history reports the 10 TNB Treasury fee, not the founder change');assert.equal(senderView.getBigUint64(4+56,true),1n,'asset creation fee is sent');assert.equal(senderView.getBigUint64(4+64+16,true),10000000002n,'funding output is reported as received');assert.equal(senderView.getBigUint64(4+64+56,true),0n,'funding output direction is received');
 const recipientHistory=call('wallet_seed_history_v2',[recipient,blocks,blocks.length],4+4096*64);assert.equal(recipientHistory.count,0,'unrelated wallet must not see asset-fee change as received TNB');
 console.log('PASS: asset creation-fee transactions and their change are included in wallet history.');
}else{
 const after=fs.readFileSync(root+'after.bin');const expected=JSON.parse(fs.readFileSync(root+'expected.json'));
 for(const [seed,direction,name] of [[sender,1n,'sender'],[recipient,0n,'recipient']]){
  const balance=call('wallet_seed_balance',[seed,after,after.length],8);assert.equal(balance.count,1);assert.equal(new DataView(balance.bytes.buffer).getBigUint64(0,true).toString(),expected[name]);
  const history=call('wallet_seed_history_v2',[seed,after,after.length],4+4096*64);assert.equal(history.count,1,`${name}: change must not appear as a second payment`);const view=new DataView(history.bytes.buffer);assert.equal(view.getBigUint64(4+16,true),100n);assert.equal(view.getBigUint64(4+56,true),direction);
 }
 assert.equal(expected.recipient,'100');
 console.log('PASS: WASM balance matches native consensus after confirmation; sent and received histories each contain one correct payment.');
}
