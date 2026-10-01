const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const test=require('node:test');
const html=fs.readFileSync('web-wallet.html','utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(source);
function wallet(){
 const elements=new Map();
 const element=id=>{if(!elements.has(id))elements.set(id,{textContent:'',value:'',hidden:false,children:[],style:{},parentNode:{insertBefore(){}},classList:{toggle(){}},addEventListener(){},setAttribute(){},focus(){},scrollIntoView(){},replaceChildren(){this.children=[];this.textContent='';},appendChild(row){this.children.push(row);}});return elements.get(id);};
 const store=new Map(),sessionStore=new Map();
 const messageHandlers=[];const ctx=vm.createContext({TextEncoder,TextDecoder,Uint8Array,DataView,BigInt,URL,URLSearchParams,AbortController,crypto:webcrypto,btoa,atob,console,setTimeout,clearTimeout,setInterval:()=>1,clearInterval:()=>{},location:{href:'https://wallet.test/web-wallet.html',origin:'https://wallet.test',protocol:'https:',search:''},document:{getElementById:element,createElement:()=>({textContent:'',value:'',className:'',title:'',children:[],style:{},setAttribute(){},focus(){},scrollIntoView(){},appendChild(child){this.children.push(child);}})},localStorage:{getItem:k=>store.get(k)||null,setItem:(k,v)=>store.set(k,v),removeItem:k=>store.delete(k)},sessionStorage:{getItem:k=>sessionStore.get(k)||null,setItem:(k,v)=>sessionStore.set(k,v),removeItem:k=>sessionStore.delete(k)},addEventListener:(type,handler)=>{if(type==='message')messageHandlers.push(handler);}});
 ctx.window=ctx;ctx.fetch=async()=>{throw Error('Unexpected network request');};
 vm.runInContext(source.slice(0,source.indexOf('const deviceModeKey=')),ctx);
 return {ctx,element,messageHandlers,run:code=>vm.runInContext(code,ctx)};
}
test('TNB amounts are exact; zero, excessive precision and overflow are rejected',()=>{
 const {run}=wallet();assert.equal(run("tnbToNox('12.000000001')"),12000000001n);
 for(const value of ['0','-1','NaN','1.0000000001','18446744073.709551616'])assert.throws(()=>run(`tnbToNox('${value}')`));
 assert.equal(run('formatNox(18446744073709551615n)'),'18446744073.709551615');
});
test('base64 encoding supports maximum transaction sizes without stack overflow',()=>{
 const {ctx,run}=wallet();ctx.bytes=new Uint8Array(512*1024).fill(123);assert.equal(run('b64ToBytes(bytesToB64(bytes)).length'),512*1024);
});
test('saved wallet records stay independent and require the selected wallet password',async()=>{
 const {ctx,run}=wallet();run("wasmAddress=async seed=>'tsc1_'+seed[0];refreshSavedWalletSelector=()=>{}");ctx.firstSeed=new Uint8Array(32).fill(11);ctx.secondSeed=new Uint8Array(32).fill(22);
 const firstAddress=await run("encrypt(firstSeed,'first-local-password')");const secondAddress=await run("encrypt(secondSeed,'second-local-password')");ctx.firstAddress=firstAddress;ctx.secondAddress=secondAddress;
 const records=JSON.parse(ctx.localStorage.getItem('tenebra.wallets.v1'));assert.equal(Object.keys(records).length,2);
 assert.deepEqual([...await run("decrypt('first-local-password',firstAddress)")],[...ctx.firstSeed]);assert.deepEqual([...await run("decrypt('second-local-password',secondAddress)")],[...ctx.secondSeed]);
 await assert.rejects(run("decrypt('first-local-password',secondAddress)"),/Wrong password/);
 await assert.rejects(run("decrypt('first-local-password')"),/Choose the wallet/);
});
test('pending transfers belong to their wallet, not to the whole browser',()=>{
 const {element,run}=wallet();element('address').textContent='wallet-a';run("addTransferHistoryEntry({txid:'a'})");element('address').textContent='wallet-b';assert.equal(run('getTransferHistory().length'),0);element('address').textContent='wallet-a';assert.equal(run('getTransferHistory()[0].txid'),'a');
});
test('Coins and NFTs appear before transaction history and mining',()=>{
 const coins=html.indexOf('id="assets-panel"'),history=html.indexOf('id="tx-history"'),mining=html.indexOf('id="mining"');
 assert.ok(coins>=0&&coins<history&&history<mining);
});
test('full-chain scans, transfer signing and asset creation use a 15-minute timeout',async()=>{
 const {ctx,run}=wallet();run('unlocked=new Uint8Array(32)');ctx.timeoutValues=[];ctx.setTimeout=(_callback,delay)=>{ctx.timeoutValues.push(delay);return ctx.timeoutValues.length;};ctx.clearTimeout=()=>{};ctx.Blob=Blob;ctx.URL=class extends URL{static createObjectURL(){return 'blob:test';}};ctx.Worker=class{constructor(){ctx.worker=this;}postMessage(message){ctx.workerMessage=message;}terminate(){}};
 const scan=run("scanWalletInWorker('wallet_seed_history_v2',262148,new Uint8Array([1]))");assert.equal(ctx.timeoutValues.at(-1),900000);ctx.worker.onmessage({data:{count:0,bytes:new ArrayBuffer(0)}});await scan;
 const signing=run("signTransferInWorker('tsc1_test',1n,1n,new Uint8Array([1]))");assert.equal(ctx.timeoutValues.at(-1),900000);ctx.worker.onmessage({data:{count:1,bytes:new Uint8Array([7]).buffer}});assert.deepEqual([...await signing],[7]);
 const assetSigning=run("signAssetCreateInWorker('NFT','NFT',0,1n,1n,new Uint8Array([1]),{assetKind:1})");assert.equal(ctx.timeoutValues.at(-1),900000);assert.equal(ctx.workerMessage.assetKind,1);ctx.worker.onmessage({data:{count:1,bytes:new Uint8Array([8]).buffer}});assert.deepEqual([...await assetSigning],[8]);
});
test('chain download is shared and checks page counts and final tip',async()=>{
 const {ctx,run}=wallet();let calls=0;ctx.fetch=async url=>{calls++;return {ok:true,status:200,json:async()=>new URL(url).pathname==='/api/status'?{height:1,tip:'tip'}:{start:1,count:1,tip:'tip',blocks:[btoa('block')]}};};
 const [a,b]=await Promise.all([run('downloadChain()'),run('downloadChain()')]);assert.equal(calls,2);assert.equal(a,b);assert.equal(new DataView(a.buffer).getUint32(0,true),5);
 run('chainCache=null');ctx.fetch=async url=>({ok:true,status:200,json:async()=>new URL(url).pathname==='/api/status'?{height:1,tip:'tip'}:{start:1,count:2,tip:'tip',blocks:[btoa('block')]}});await assert.rejects(run('downloadChain()'),/Invalid public chain page/);
});
test('token chain download reports progress for each sequential block page',async()=>{
 const {ctx,run}=wallet();ctx.progress=[];ctx.fetch=async url=>{const parsed=new URL(url);return{ok:true,status:200,json:async()=>parsed.pathname==='/api/status'?{height:2,tip:'tip-2'}:{start:parsed.searchParams.get('from')==='1'?1:2,count:1,tip:parsed.searchParams.get('from')==='1'?'tip-1':'tip-2',blocks:[btoa('block')]}};};
 await run('downloadChain(message=>progress.push(message))');assert.equal(ctx.progress.length,3);assert.match(ctx.progress[0],/Downloading confirmed blocks 1-2 of 2 for token signing/);assert.match(ctx.progress[1],/Downloading confirmed blocks 2-2 of 2 for token signing/);assert.match(ctx.progress[2],/Chain synchronized through block 2/);
});
test('token chain download retries a page after a temporary peer disconnect',async()=>{
 const {ctx,run}=wallet();ctx.progress=[];ctx.pageAttempts=0;run("apiFetch=async url=>{if(url==='/api/status')return{ok:true,json:async()=>({height:1,tip:'tip-1'})};if(++globalThis.pageAttempts===1)throw Error('peer closed connection');return{ok:true,json:async()=>({start:1,count:1,tip:'tip-1',blocks:[btoa('block')]})}};setTimeout=callback=>{callback();return 1}");
 const chain=await run('downloadChain(message=>progress.push(message))');assert.equal(ctx.pageAttempts,2);assert.equal(new DataView(chain.buffer).getUint32(0,true),5);assert.ok(ctx.progress.some(message=>message.includes('Peer connection interrupted')&&message.includes('retrying (1/3)')));assert.match(ctx.progress.at(-1),/Chain synchronized through block 1/);
});
test('chain cache with the same height but a different tip is rebuilt from genesis',async()=>{
 const {ctx,run}=wallet();ctx.requests=[];run("chainCache=null;readChainCache=async()=>({height:1,tip:'old-tip',bytes:new Uint8Array([1,0,0,0,1])});writeChainCache=async snapshot=>{globalThis.savedSnapshot=snapshot}");
 ctx.fetch=async url=>{const parsed=new URL(url);ctx.requests.push(parsed.pathname+parsed.search);return{ok:true,status:200,json:async()=>parsed.pathname==='/api/status'?{height:1,tip:'new-tip'}:{start:1,count:1,tip:'new-tip',blocks:[btoa('block')]}};};
 await run('downloadChain()');assert.equal(ctx.requests.length,2);assert.match(ctx.requests[1],/from=1&limit=1/);assert.doesNotMatch(ctx.requests[1],/anchor=/);assert.equal(ctx.savedSnapshot.tip,'new-tip');
});
test('invalid cached anchor triggers one full-chain retry',async()=>{
 const {ctx,run}=wallet();ctx.requests=[];run("chainCache=null;readChainCache=async()=>({height:1,tip:'stale-tip',bytes:new Uint8Array([1,0,0,0,1])});writeChainCache=async snapshot=>{globalThis.savedSnapshot=snapshot}");
 ctx.fetch=async url=>{const parsed=new URL(url);ctx.requests.push(parsed.pathname+parsed.search);if(parsed.pathname==='/api/status')return{ok:true,status:200,json:async()=>({height:2,tip:'current-tip'})};if(parsed.searchParams.has('anchor'))return{ok:false,status:400,json:async()=>({error:'invalid local block anchor'})};return{ok:true,status:200,json:async()=>({start:1,count:2,tip:'current-tip',blocks:[btoa('block-1'),btoa('block-2')]})};};
 await run('downloadChain()');assert.equal(ctx.requests.length,4);assert.match(ctx.requests[1],/anchor=stale-tip/);assert.match(ctx.requests[3],/from=1&limit=2/);assert.doesNotMatch(ctx.requests[3],/anchor=/);assert.equal(ctx.savedSnapshot.tip,'current-tip');
});
test('API retries a transient 503 without duplicating the same origin',async()=>{
 const {ctx,run}=wallet();ctx.location.hostname='tenebra-network.com';ctx.location.origin='https://tenebra-network.com';let calls=0;
 ctx.fetch=async()=>{calls++;return calls===1?{ok:false,status:503}:{ok:true,status:200};};const response=await run("apiFetch('/api/status')");
 assert.equal(response.status,200);assert.equal(calls,2);
});
test('balance explains its local source and index fallback state',async()=>{
 const {run,element}=wallet();element('address').textContent='tsc1_test';run("unlocked=new Uint8Array(32);chainCache={height:9250};scanBalance=async()=>1234567890n;readAddressRecord=async()=>({indexed:false});renderHistoryPanel=async()=>{}");await run('updateBalance()');
 assert.equal(element('balance').textContent,'Balance: 1.234567890 TNB');assert.match(element('balance-detail').textContent,/locally from confirmed blocks through height 9250/);assert.equal(element('refresh-balance').disabled,false);
 run("scanBalance=async()=>{throw Error('Public block download failed (HTTP 503)')};readAddressRecord=async()=>({indexed:false})");await run('updateBalance(true)');
 assert.equal(element('balance').textContent,'Last confirmed balance: 1.234567890 TNB');assert.match(element('balance-detail').textContent,/Latest refresh failed: Public block download failed \(HTTP 503\).*saved balance/);
});
test('last confirmed balance is shown during sync and refreshed value is saved',async()=>{
 const {ctx,run,element}=wallet();element('address').textContent='tsc1_test';ctx.localStorage.setItem('tenebra.wallet.balance.v1:tsc1_test',JSON.stringify({balance_nox:'1234567890',height:9250}));
 run("unlocked=new Uint8Array(32);scanBalance=()=>new Promise(resolve=>globalThis.finishBalanceScan=resolve);readAddressRecord=async()=>({indexed:false});renderHistoryPanel=async()=>{}");const refresh=run('updateBalance(true)');
 assert.equal(element('balance').textContent,'Last confirmed balance: 1.234567890 TNB');assert.match(element('balance-detail').textContent,/Saved locally through height 9250; synchronizing/);
 ctx.finishBalanceScan(2000000000n);await refresh;assert.equal(element('balance').textContent,'Balance: 2.000000000 TNB');assert.equal(JSON.parse(ctx.localStorage.getItem('tenebra.wallet.balance.v1:tsc1_test')).balance_nox,'2000000000');
});
test('unlock establishes a shared connected-wallet session',async()=>{
 const {ctx,run,element}=wallet();run("wasmAddress=async()=> 'tsc1_test';renderQr=()=>{};updateAssets=()=>{};updateBalance=()=>{globalThis.refreshed=true;};startBalanceRefresh=()=>{globalThis.started=true;}");ctx.seed=new Uint8Array(32).fill(4);await run('show(seed)');assert.equal(ctx.refreshed,true);assert.equal(ctx.started,true);assert.equal(element('wallet').hidden,false);assert.equal(run('unlocked===seed'),true);assert.equal(ctx.localStorage.getItem('tenebra.connected.address'),'tsc1_test');assert.equal(ctx.localStorage.getItem('tenebra.wallet.session.address'),'tsc1_test');
 assert.equal(ctx.localStorage.getItem('tenebra.wallet.autologin.v1'),null);
});
test('persistent wallet session encrypts the seed and can be cleared on logout',async()=>{
 const {ctx,run}=wallet();const records=new Map();let hasStore=false;ctx.indexedDB={open(){const request={};const db={objectStoreNames:{contains:()=>hasStore},createObjectStore(){hasStore=true;},close(){},transaction(){const transaction={};transaction.objectStore=()=>({put(value,key){const result={};queueMicrotask(()=>{records.set(key,value);result.result=key;result.onsuccess?.();transaction.oncomplete?.();});return result;},get(key){const result={};queueMicrotask(()=>{result.result=records.get(key);result.onsuccess?.();transaction.oncomplete?.();});return result;},delete(key){const result={};queueMicrotask(()=>{records.delete(key);result.onsuccess?.();transaction.oncomplete?.();});return result;}});return transaction;}};queueMicrotask(()=>{request.result=db;request.onupgradeneeded?.();request.onsuccess?.();});return request;}};
 ctx.seed=new Uint8Array(32).fill(29);await run("savePersistentWalletSession('wallet-a',seed)");const record=records.get('wallet-a');assert.ok(record.key);assert.notDeepEqual([...Uint8Array.from(Buffer.from(record.cipher,'base64'))],[...ctx.seed]);assert.deepEqual([...await run("loadPersistentWalletSession('wallet-a')")],new Array(32).fill(29));ctx.localStorage.setItem('tenebra.wallet.session.address','wallet-b');ctx.sessionStorage.setItem('tenebra.wallet.session.address','wallet-a');run("loadSigner=async()=>{};wasmAddress=async()=> 'wallet-a';show=async seed=>{globalThis.restoredSeed=Array.from(seed)}");const restoreStart=html.indexOf('async function restoreAutoLogin()');run(html.slice(restoreStart,html.indexOf('\n',restoreStart)));await run('restoreAutoLogin()');assert.deepEqual(Array.from(ctx.restoredSeed),new Array(32).fill(29));assert.equal(ctx.localStorage.getItem('tenebra.wallet.session.address'),'wallet-b');await run("clearPersistentWalletSession('wallet-a')");assert.equal(await run("loadPersistentWalletSession('wallet-a')"),null);
});
test('token login transfers the signer session to the hidden frame and closes its popup',async()=>{
 const {ctx,messageHandlers,run}=wallet();ctx.location.search='?connect=create-token&state=nonce';let transferred=null;ctx.closed=false;ctx.close=()=>{ctx.closed=true;};const frame={contentWindow:{postMessage:message=>{transferred=message;}}};ctx.opener={closed:false,document:{getElementById:()=>frame}};run("wasmAddress=async()=> 'tsc1_test';renderQr=()=>{};updateAssets=()=>{};updateBalance=()=>{};startBalanceRefresh=()=>{}");ctx.seed=new Uint8Array(32).fill(4);await run('show(seed)');
 assert.equal(ctx.closed,false);run('tokenWalletFrameReady=true');await messageHandlers[0]({origin:'https://wallet.test',source:ctx.opener,data:{type:'tenebra:wallet-frame-ready',state:'nonce'}});
 assert.equal(transferred.type,'tenebra:install-wallet-session');assert.equal(transferred.state,'nonce');assert.deepEqual([...transferred.seed],new Array(32).fill(4));assert.equal(ctx.closed,false);assert.equal(run('unlocked')===ctx.seed,true);
 await messageHandlers[0]({origin:'https://wallet.test',source:ctx.opener,data:{type:'tenebra:wallet-session-installed',state:'nonce'}});assert.equal(ctx.closed,true);assert.equal(run('unlocked'),null);assert.ok([...ctx.seed].every(byte=>byte===0));
});
test('hidden frame installs the transferred seed before reporting a connected wallet',async()=>{
 const {ctx,messageHandlers,run,element}=wallet();ctx.location.search='?connect=create-token-session&state=nonce';let response=null;const parentWindow={postMessage:message=>{response=message;}};ctx.parent=parentWindow;const popup={opener:parentWindow,postMessage(){}};run("loadSigner=async()=>{};show=async seed=>{globalThis.receivedSeed=Array.from(seed);document.getElementById('address').textContent='tsc1_installed';}");
 await messageHandlers[0]({origin:'https://wallet.test',source:popup,data:{type:'tenebra:install-wallet-session',state:'nonce',seed:new Array(32).fill(7)}});
 assert.equal(response.type,'tenebra:wallet-connected');assert.equal(response.address,'tsc1_installed');assert.deepEqual(Array.from(ctx.receivedSeed),new Array(32).fill(7));assert.equal(element('address').textContent,'tsc1_installed');
});
test('token creation requests are accepted by the hidden frame and report completion',async()=>{
 const {ctx,messageHandlers,run}=wallet();ctx.location.search='?connect=create-token-session&state=nonce';let responses=[];const parentWindow={postMessage:message=>{responses.push(message);}};ctx.parent=parentWindow;run('unlocked=new Uint8Array(32)');ctx.resumeTokenCreate=async(draft,report)=>{report(`Token submitted. TXID ${'a'.repeat(64)}.`);return{ok:true,submitted:true,confirmed:true,txid:'a'.repeat(64),assetId:'b'.repeat(64),message:`${draft.symbol} confirmed`};};
 await messageHandlers[0]({origin:'https://wallet.test',source:run('window.parent'),data:{type:'tenebra:create-token',state:'nonce',draft:{name:'Example Token',symbol:'ENT',decimals:9,maxSupply:'100',initialSupply:'100'}}});
 assert.ok(responses.some(message=>message.type==='tenebra:token-progress'&&message.message.includes('TXID')));assert.equal(responses.at(-1).type,'tenebra:token-result');assert.equal(responses.at(-1).state,'nonce');assert.equal(responses.at(-1).ok,true);assert.equal(responses.at(-1).confirmed,true);assert.equal(responses.at(-1).message,'ENT confirmed');
});
test('token page logout clears the iframe wallet session and acknowledges the disconnect',async()=>{
 const {ctx,messageHandlers,run}=wallet();ctx.location.search='?connect=create-token-session&state=nonce';const parentWindow={postMessage(){}};ctx.parent=parentWindow;ctx.disconnected=false;run('unlocked=new Uint8Array(32)');ctx.disconnectWalletSession=()=>{run('unlocked.fill(0);unlocked=null');ctx.disconnected=true;};
 let response=null;const source=run('window.parent');source.postMessage=message=>{response=message;};await messageHandlers[0]({origin:'https://wallet.test',source,data:{type:'tenebra:disconnect-wallet',state:'nonce'}});
 assert.equal(ctx.disconnected,true);assert.equal(run('unlocked'),null);assert.equal(response.type,'tenebra:wallet-disconnected');assert.equal(response.state,'nonce');
});
test('history merges block inclusion with pending entry and renders untrusted data as text',async()=>{
 const {run,element}=wallet();element('address').textContent='wallet-a';run("unlocked=new Uint8Array(32);downloadChain=async()=>new Uint8Array();setHistoryMode('transfers');addTransferHistoryEntry({txid:'same',time:'2026-01-01',amount:'1',direction:'send'});scanIncoming=async()=>[{txid:'same',height:'19220',confirmations:0,time:'2026-01-01',amount:'1',direction:'send',status:'included'},{txid:'<img onerror=bad>',height:'19219',confirmations:1,time:'2026-01-02',amount:'2',direction:'receive',status:'included'}]");await run('renderHistoryPanel()');assert.equal(element('history-content').children.length,2);assert.match(element('history-content').children[0].textContent,/<img onerror=bad>/);assert.match(element('history-content').children[1].textContent,/Confirmed in block #19220; finality 0\/10/);
});
test('confirmed incoming transactions are shown before pending sends',async()=>{
 const {run,element}=wallet();element('address').textContent='wallet-a';run("unlocked=new Uint8Array(32);downloadChain=async()=>new Uint8Array();setHistoryMode('transfers');addTransferHistoryEntry({txid:'pending',time:'2026-09-30T14:37:25.690Z',amount:'100',direction:'send',status:'submitted'});scanIncoming=async()=>[{txid:'received',height:'19938',confirmations:551,time:'2026-09-30T03:26:48.000Z',amount:'9874088.33',direction:'receive',status:'included'}]");await run('renderHistoryPanel()');const rows=element('history-content').children;assert.equal(rows.length,2);assert.match(rows[0].textContent,/Received/);assert.match(rows[0].textContent,/Confirmed in block #19938/);assert.match(rows[1].textContent,/Sent/);assert.match(rows[1].textContent,/Submitted; awaiting block inclusion/);
});
test('transaction inclusion poll exits before ten finality confirmations',async()=>{
 const {ctx,run}=wallet();ctx.searchResponses=[{found:false,indexing:true},{found:true,kind:'transaction',block:{height:19220},transaction:{txid:'a'.repeat(64),confirmations:0}}];run('apiFetch=async()=>({ok:true,json:async()=>searchResponses.shift()})');ctx.setTimeout=callback=>{callback();return 1;};const result=await run(`waitForTransactionInclusion('${'a'.repeat(64)}',3)`);assert.equal(result.block_height,19220);assert.equal(result.confirmations,0);
});
test('asset panel reports index progress and retries before declaring no owned assets',async()=>{
 const {ctx,run,element}=wallet();ctx.assetResponses=[{assets:[],indexing:true,indexed_height:64,target_height:100},{assets:[],indexing:false,indexed:true,indexed_height:100,target_height:100}];ctx.setTimeout=(callback,delay)=>{ctx.assetRetry=callback;ctx.assetRetryDelay=delay;return 1;};ctx.clearTimeout=()=>{};
 ctx.localStorage.setItem('tenebra.wallet.balance.v1:tsc1_test',JSON.stringify({balance_nox:'5000000000'}));run("apiFetch=async()=>({ok:true,json:async()=>assetResponses.shift()})");await run("updateAssets('tsc1_test')");assert.match(element('assets').children[1].textContent,/Indexing through block 64 of 100/);assert.equal(element('assets').children[0].children[1].children[2].textContent,'5.000000000 TNB');assert.match(element('nfts').textContent,/Indexing through block 64 of 100/);assert.equal(ctx.assetRetryDelay,5000);
 await ctx.assetRetry();assert.equal(element('assets').children.length,1);assert.equal(element('nfts').textContent,'No NFTs detected.');
});
test('Coins keeps TNB and tokens separate from the NFT list',async()=>{
 const {run,element,ctx}=wallet();ctx.localStorage.setItem('tenebra.my-nfts.v1',JSON.stringify([{assetId:'a'.repeat(64),image:'data:image/webp;base64,AAAA'}]));
 ctx.localStorage.setItem('tenebra.wallet.balance.v1:tsc1_test',JSON.stringify({balance_nox:'5000000000'}));
 run("apiFetch=async()=>({ok:true,json:async()=>({assets:[{name:'NFT One',symbol:'ONE',asset_id:'a'.repeat(64),balance:1,decimals:0,max_supply:1},{name:'the first spark',symbol:'TFS',asset_id:'b'.repeat(64),balance:1,decimals:0,max_supply:1},{name:'Unlinked NFT',symbol:'UNK',asset_id:'c'.repeat(64),balance:1,decimals:0,max_supply:1},{name:'ELENA',symbol:'ELE',asset_id:'d'.repeat(64),balance:1234,decimals:2,max_supply:1000000000}],indexed:true,indexing:false})})");await run("updateAssets('tsc1_test')");
 const coins=element('assets').children,nfts=element('nfts').children;assert.equal(coins.length,2);assert.equal(nfts.length,3);assert.ok([...coins,...nfts].every(row=>row.className==='asset-row'));
 assert.equal(coins[0].children[1].children[0].textContent,'TENEBRA');assert.equal(coins[0].children[1].children[1].textContent,'Native coin');assert.equal(coins[0].children[1].children[2].textContent,'5.000000000 TNB');assert.equal(coins[1].children[1].children[0].textContent,'ELENA');assert.equal(coins[1].children[1].children[1].textContent,'ELE · Token');assert.equal(coins[1].children[1].children[2].textContent,'12.34 ELE');
 assert.equal(nfts[0].children[0].children[0].src,'data:image/webp;base64,AAAA');assert.equal(nfts[1].children[0].children[0].src,'assets/founder-artwork/01-the-first-spark.jpg');assert.equal(nfts[2].children[0].textContent,'UNK');assert.equal(nfts[2].children[1].children[1].textContent,'NFT');assert.equal(nfts[2].children[2].textContent,'Send');assert.match(nfts[0].children[1].title,/a{64}/);
 nfts[0].children[2].onclick();assert.equal(element('asset-id-transfer').value,'a'.repeat(64));assert.equal(element('asset-amount-transfer').value,'1');
});
test('saved local token logo is rendered for fungible assets',()=>{
 const {ctx,run}=wallet();const assetId='a'.repeat(64),logo='data:image/webp;base64,AAAA';ctx.localStorage.setItem(`tenebra.token.logo.v1:${assetId}`,logo);
 const row=run(`createWalletAssetRow({asset_id:'${assetId}',name:'ELENA',symbol:'ELE',balance_units:'1',decimals:0})`);
 assert.equal(row.children[0].children[0].src,logo);assert.equal(row.children[1].children[0].textContent,'ELENA');
});
test('issuer admin lists only assets created by the logged-in wallet',async()=>{
 const {ctx,run,element}=wallet();const issuer='11'.repeat(32);element('address').textContent=`tsc1_${'00'.repeat(32)}${issuer}${'00'.repeat(4)}`;
 run(`apiFetch=async()=>({ok:true,json:async()=>({assets:[{name:'Owned Coin',symbol:'OWN',asset_id:'a'.repeat(64),issuer:'${issuer}',balance_units:'0',minted_units:'100000000000000000',max_supply_units:'200000000000000000',balance:0,minted:100000000000000000,max_supply:200000000000000000,decimals:9,mintable:true,burnable:false},{name:'Owned NFT',symbol:'ONFT',asset_id:'c'.repeat(64),issuer:'${issuer}',balance_units:'1',minted_units:'1',max_supply_units:'1',balance:1,minted:1,max_supply:1,decimals:0,mintable:false,burnable:false},{name:'Other Coin',symbol:'OTH',asset_id:'b'.repeat(64),issuer:'${'22'.repeat(32)}',balance_units:'1',minted_units:'1',max_supply_units:'2',balance:1,minted:1,max_supply:2,decimals:0,mintable:false,burnable:false}],indexed:true,indexing:false})})`);
 await run("updateAssets(document.getElementById('address').textContent)");
 assert.equal(element('issuer-tools').hidden,false);assert.equal(element('issuer-assets').children.length,1);assert.match(element('issuer-assets').children[0].children[0].children[0].textContent,/Owned Coin/);
 element('issuer-assets').children[0].children[1].onclick();assert.equal(element('issuer-admin').hidden,false);assert.equal(element('issuer-admin-title').textContent,'Administrează Owned Coin (OWN)');assert.equal(element('issuer-mint').disabled,false);assert.equal(element('issuer-burn').disabled,true);
});
test('Receive, QR, asset tabs, and send forms open only on demand',async()=>{
 const {run,element}=wallet();
 element('receive-details').hidden=true;element('qr').hidden=true;element('tnb-send-form').hidden=true;element('asset-transfer-form').hidden=true;element('coins-view').hidden=false;element('nfts-view').hidden=true;
 run("apiFetch=async()=>({ok:true,json:async()=>({assets:[{name:'ELENA',symbol:'ELE',asset_id:'e'.repeat(64),balance:2500,decimals:2,max_supply:1000000},{name:'One NFT',symbol:'NFT',asset_id:'f'.repeat(64),balance:1,decimals:0,max_supply:1}],indexed:true,indexing:false})})");
 await run("updateAssets('tsc1_test')");
 assert.equal(element('receive-details').hidden,true);assert.equal(element('qr').hidden,true);assert.equal(element('nfts-view').hidden,true);assert.equal(element('tnb-send-form').hidden,true);assert.equal(element('asset-transfer-form').hidden,true);
 run("document.getElementById('receive-toggle').onclick()");assert.equal(element('receive-details').hidden,false);
 run("document.getElementById('qr-toggle').onclick()");assert.equal(element('qr').hidden,false);
 run("document.getElementById('assets').children[0].children[2].onclick()");assert.equal(element('tnb-send-form').hidden,false);assert.equal(element('asset-transfer-form').hidden,true);
 run("document.getElementById('cancel-tnb-send').onclick()");run("document.getElementById('assets').children[1].children[2].onclick()");assert.equal(element('asset-transfer-form').hidden,false);assert.equal(element('asset-id-transfer').value,'e'.repeat(64));assert.equal(element('asset-amount-transfer').value,'25');
 run("document.getElementById('cancel-asset-transfer').onclick()");run("document.getElementById('nfts-tab').onclick()");assert.equal(element('coins-view').hidden,true);assert.equal(element('nfts-view').hidden,false);run("document.getElementById('nfts').children[0].children[2].onclick()");assert.equal(element('asset-transfer-form').hidden,false);assert.equal(element('asset-id-transfer').value,'f'.repeat(64));
});
test('WASM allocations are zeroed and freed even when an operation throws',()=>{
 const {ctx,run}=wallet();ctx.memory={buffer:new ArrayBuffer(256)};ctx.freed=[];run('wasm={exports:{memory,wallet_alloc:()=>8,wallet_free:(ptr,size)=>freed.push([ptr,size])}}');assert.throws(()=>run("withWalletMemory(alloc=>{alloc(new Uint8Array([1,2,3]));throw Error('test');})"));assert.equal(ctx.freed.length,1);assert.deepEqual([...new Uint8Array(ctx.memory.buffer,8,3)],[0,0,0]);
});
