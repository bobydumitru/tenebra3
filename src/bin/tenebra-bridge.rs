use std::{env, process};
use tenebra::bridge::{BroadcastRequest, BridgeChain, OperationStatus, RpcConfig, RpcExecutor, TransferDirection, VaultLedger};

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  tenebra-bridge broadcast <solana|evm|bitcoin> <operation-id> <raw-tx> <asset> <amount> <owner> <credit|debit>");
    eprintln!("  tenebra-bridge confirm <solana|evm|bitcoin> <operation-id> <txid> <asset> <amount> <owner> <credit|debit> <ledger-path>");
    eprintln!("  TENEBRA_BRIDGE_ENVIRONMENT=mainnet|testnet|devnet selects the RPC environment.");
    process::exit(2);
}

fn chain(value: &str) -> BridgeChain {
    match value.to_ascii_lowercase().as_str() {
        "solana" => BridgeChain::Solana,
        "evm" | "ethereum" => BridgeChain::Evm,
        "bitcoin" | "btc" => BridgeChain::Bitcoin,
        _ => usage(),
    }
}

fn direction(value: &str) -> TransferDirection {
    match value.to_ascii_lowercase().as_str() {
        "credit" | "deposit" => TransferDirection::Credit,
        "debit" | "withdrawal" => TransferDirection::Debit,
        _ => usage(),
    }
}

fn amount(value: &str) -> u128 { value.parse().unwrap_or_else(|_| usage()) }

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("broadcast") if args.len() == 9 => {
            let chain = chain(&args[2]);
            let request = BroadcastRequest {
                operation_id: args[3].clone(), chain,
                raw_transaction: args[4].clone(), asset: args[5].clone(), amount: amount(&args[6]),
                owner: args[7].clone(), direction: direction(&args[8]),
            };
            let config = RpcConfig::from_runtime_env(chain).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            match RpcExecutor::new(config).broadcast(&request) {
                Ok(receipt) => println!("{}", serde_json::to_string(&receipt).expect("receipt serialization")),
                Err(error) => { eprintln!("{error}"); process::exit(1); }
            }
        }
        Some("confirm") if args.len() == 10 => {
            let chain = chain(&args[2]);
            let config = RpcConfig::from_runtime_env(chain).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            let executor = RpcExecutor::new(config);
            let status = executor.confirmation(&args[4]).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            println!("status={status:?}");
            if status != OperationStatus::Finalized { return; }
            let request = BroadcastRequest {
                operation_id: args[3].clone(), chain, raw_transaction: "confirmation-only".into(),
                asset: args[5].clone(), amount: amount(&args[6]), owner: args[7].clone(), direction: direction(&args[8]),
            };
            let receipt = tenebra::bridge::BroadcastReceipt {
                operation_id: request.operation_id.clone(), chain, transaction_id: args[4].clone(), status,
            };
            let mut ledger = VaultLedger::load(&args[9]).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            ledger.apply_finalized(&receipt, &request).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            ledger.persist(&args[9]).unwrap_or_else(|error| { eprintln!("{error}"); process::exit(1); });
            println!("settled operation={} asset={} amount={} direction={:?}", request.operation_id, request.asset, request.amount, request.direction);
        }
        _ => usage(),
    }
}
