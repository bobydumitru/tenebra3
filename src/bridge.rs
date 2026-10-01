use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BridgeChain {
    Solana,
    Evm,
    Bitcoin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BridgeEnvironment {
    Mainnet,
    Testnet,
    Devnet,
}

impl BridgeChain {
    pub fn rpc_method(self) -> &'static str {
        match self {
            Self::Solana => "sendTransaction",
            Self::Evm => "eth_sendRawTransaction",
            Self::Bitcoin => "sendrawtransaction",
        }
    }

    pub fn finality_confirmations(self) -> u64 {
        match self {
            Self::Solana => 32,
            Self::Evm => 12,
            Self::Bitcoin => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcConfig {
    pub chain: BridgeChain,
    pub environment: BridgeEnvironment,
    pub url: String,
    pub api_key: Option<String>,
}

impl RpcConfig {
    pub fn from_env(chain: BridgeChain) -> Result<Self, String> {
        Self::from_environment(chain, BridgeEnvironment::Mainnet)
    }

    pub fn from_runtime_env(chain: BridgeChain) -> Result<Self, String> {
        let environment = match std::env::var("TENEBRA_BRIDGE_ENVIRONMENT").unwrap_or_else(|_| "testnet".into()).to_ascii_lowercase().as_str() {
            "mainnet" => BridgeEnvironment::Mainnet,
            "testnet" => BridgeEnvironment::Testnet,
            "devnet" => BridgeEnvironment::Devnet,
            value => return Err(format!("unsupported TENEBRA_BRIDGE_ENVIRONMENT: {value}")),
        };
        if environment == BridgeEnvironment::Mainnet && std::env::var("TENEBRA_BRIDGE_ALLOW_MAINNET").as_deref() != Ok("true") {
            return Err("mainnet broadcast is disabled; set TENEBRA_BRIDGE_ALLOW_MAINNET=true only after testnet validation".into());
        }
        Self::from_environment(chain, environment)
    }

    pub fn from_environment(chain: BridgeChain, environment: BridgeEnvironment) -> Result<Self, String> {
        let environment_key = match environment {
            BridgeEnvironment::Mainnet => "",
            BridgeEnvironment::Testnet => "_TESTNET",
            BridgeEnvironment::Devnet => "_DEVNET",
        };
        let (url_key, key_key) = match chain {
            BridgeChain::Solana => (format!("TENEBRA_SOLANA{environment_key}_RPC_URL"), format!("TENEBRA_SOLANA{environment_key}_RPC_KEY")),
            BridgeChain::Evm => (format!("TENEBRA_EVM{environment_key}_RPC_URL"), format!("TENEBRA_EVM{environment_key}_RPC_KEY")),
            BridgeChain::Bitcoin => (format!("TENEBRA_BITCOIN{environment_key}_RPC_URL"), format!("TENEBRA_BITCOIN{environment_key}_RPC_KEY")),
        };
        let url = std::env::var(&url_key).map_err(|_| format!("missing {url_key}"))?;
        Ok(Self { chain, environment, url, api_key: std::env::var(key_key).ok() })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastRequest {
    pub operation_id: String,
    pub chain: BridgeChain,
    pub raw_transaction: String,
    pub asset: String,
    pub amount: u128,
    pub owner: String,
    pub direction: TransferDirection,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum TransferDirection {
    Credit,
    Debit,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastReceipt {
    pub operation_id: String,
    pub chain: BridgeChain,
    pub transaction_id: String,
    pub status: OperationStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OperationStatus {
    Broadcast,
    Confirming,
    Finalized,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LedgerOperation {
    pub operation_id: String,
    pub chain: BridgeChain,
    pub asset: String,
    pub amount: u128,
    pub owner: String,
    pub direction: TransferDirection,
    pub transaction_id: String,
    pub status: OperationStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VaultLedger {
    operations: BTreeMap<String, LedgerOperation>,
    balances: BTreeMap<(String, String), u128>,
}

impl VaultLedger {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() { return Ok(Self::default()); }
        let bytes = fs::read(path).map_err(|error| format!("read ledger: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|error| format!("decode ledger: {error}"))
    }

    pub fn persist(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let temporary = temporary_path(path);
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| format!("encode ledger: {error}"))?;
        fs::write(&temporary, bytes).map_err(|error| format!("write ledger: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("commit ledger: {error}"))
    }

    pub fn balance(&self, asset: &str, owner: &str) -> u128 {
        self.balances.get(&(asset.to_owned(), owner.to_owned())).copied().unwrap_or(0)
    }

    pub fn apply_finalized(&mut self, receipt: &BroadcastReceipt, request: &BroadcastRequest) -> Result<(), String> {
        if let Some(existing) = self.operations.get(&request.operation_id) {
            if existing.transaction_id != receipt.transaction_id { return Err("operation id reused with another transaction".into()); }
            return Ok(());
        }
        if receipt.status != OperationStatus::Finalized { return Err("only finalized operations can change balances".into()); }
        let key = (request.asset.clone(), request.owner.clone());
        let balance = self.balances.entry(key).or_default();
        match request.direction {
            TransferDirection::Credit => *balance = balance.checked_add(request.amount).ok_or("balance overflow")?,
            TransferDirection::Debit => *balance = balance.checked_sub(request.amount).ok_or("insufficient vault balance")?,
        }
        self.operations.insert(request.operation_id.clone(), LedgerOperation {
            operation_id: request.operation_id.clone(), chain: request.chain, asset: request.asset.clone(), amount: request.amount,
            owner: request.owner.clone(), direction: request.direction, transaction_id: receipt.transaction_id.clone(), status: receipt.status.clone(),
        });
        Ok(())
    }

    pub fn operation(&self, operation_id: &str) -> Option<&LedgerOperation> { self.operations.get(operation_id) }
}

pub struct RpcExecutor {
    agent: ureq::Agent,
    config: RpcConfig,
}

impl RpcExecutor {
    pub fn new(config: RpcConfig) -> Self { Self { agent: ureq::AgentBuilder::new().build(), config } }

    pub fn broadcast(&self, request: &BroadcastRequest) -> Result<BroadcastReceipt, String> {
        if request.chain != self.config.chain { return Err("RPC chain does not match transfer chain".into()); }
        if request.operation_id.trim().is_empty() || request.raw_transaction.trim().is_empty() || request.amount == 0 {
            return Err("invalid broadcast request".into());
        }
        let mut call = json!({"jsonrpc":"2.0", "id": request.operation_id, "method": request.chain.rpc_method(), "params":[request.raw_transaction]});
        if request.chain == BridgeChain::Solana { call["params"] = json!([request.raw_transaction, {"encoding":"base64","commitment":"confirmed"}]); }
        let mut http = self.agent.post(&self.config.url).set("content-type", "application/json");
        if let Some(key) = &self.config.api_key { http = http.set("authorization", &format!("Bearer {key}")); }
        let body: Value = http.send_json(call).map_err(|error| format!("RPC broadcast: {error}"))?.into_json().map_err(|error| format!("RPC response: {error}"))?;
        if let Some(error) = body.get("error") { return Err(format!("RPC rejected transaction: {error}")); }
        let transaction_id = body.get("result").and_then(Value::as_str).ok_or("RPC response has no transaction id")?.to_owned();
        Ok(BroadcastReceipt { operation_id: request.operation_id.clone(), chain: request.chain, transaction_id, status: OperationStatus::Broadcast })
    }

    pub fn confirmation(&self, transaction_id: &str) -> Result<OperationStatus, String> {
        let (method, params) = match self.config.chain {
            BridgeChain::Solana => ("getSignatureStatuses", json!([[transaction_id], {"searchTransactionHistory":true}])),
            BridgeChain::Evm => ("eth_getTransactionReceipt", json!([transaction_id])),
            BridgeChain::Bitcoin => ("gettransaction", json!([transaction_id])),
        };
        let call = json!({"jsonrpc":"2.0", "id":"confirmation", "method":method, "params":params});
        let mut http = self.agent.post(&self.config.url).set("content-type", "application/json");
        if let Some(key) = &self.config.api_key { http = http.set("authorization", &format!("Bearer {key}")); }
        let body: Value = http.send_json(call).map_err(|error| format!("RPC confirmation: {error}"))?.into_json().map_err(|error| format!("RPC response: {error}"))?;
        if body.get("error").is_some() { return Ok(OperationStatus::Failed); }
        let result = body.get("result");
        let finalized = match self.config.chain {
            BridgeChain::Solana => result.and_then(|value| value.get("value")).and_then(|value| value.get(0)).and_then(|value| value.get("confirmationStatus")).and_then(Value::as_str).is_some_and(|value| value == "finalized"),
            BridgeChain::Evm => result.is_some_and(|value| !value.is_null()),
            BridgeChain::Bitcoin => result.and_then(|value| value.get("confirmations")).and_then(Value::as_u64).is_some_and(|value| value >= self.config.chain.finality_confirmations()),
        };
        Ok(if finalized { OperationStatus::Finalized } else { OperationStatus::Confirming })
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.to_path_buf();
    temporary.set_extension("tmp");
    temporary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BroadcastRequest {
        BroadcastRequest { operation_id: "op-1".into(), chain: BridgeChain::Bitcoin, raw_transaction: "signed-raw-tx".into(), asset: "BTC".into(), amount: 100, owner: "vault-owner".into(), direction: TransferDirection::Credit }
    }

    #[test]
    fn ledger_credits_only_finalized_and_is_idempotent() {
        let request = request();
        let mut ledger = VaultLedger::default();
        let pending = BroadcastReceipt { operation_id: "op-1".into(), chain: BridgeChain::Bitcoin, transaction_id: "tx-1".into(), status: OperationStatus::Confirming };
        assert!(ledger.apply_finalized(&pending, &request).is_err());
        let finalized = BroadcastReceipt { status: OperationStatus::Finalized, ..pending };
        ledger.apply_finalized(&finalized, &request).unwrap();
        ledger.apply_finalized(&finalized, &request).unwrap();
        assert_eq!(ledger.balance("BTC", "vault-owner"), 100);
        let debit = BroadcastRequest { operation_id: "op-2".into(), direction: TransferDirection::Debit, ..request };
        let debit_receipt = BroadcastReceipt { operation_id: "op-2".into(), transaction_id: "tx-2".into(), ..finalized };
        ledger.apply_finalized(&debit_receipt, &debit).unwrap();
        assert_eq!(ledger.balance("BTC", "vault-owner"), 0);
    }

    #[test]
    fn chain_policies_are_explicit() {
        assert_eq!(BridgeChain::Solana.rpc_method(), "sendTransaction");
        assert_eq!(BridgeChain::Evm.finality_confirmations(), 12);
        assert_eq!(BridgeChain::Bitcoin.finality_confirmations(), 3);
    }
}
