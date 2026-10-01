use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        std::process::exit(2);
    }
    let challenge = match hex::decode(&args[2]) {
        Ok(bytes) => bytes,
        Err(_) => std::process::exit(2),
    };
    let signature: [u8; 64] = match hex::decode(&args[3]).and_then(|bytes| bytes.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)) {
        Ok(bytes) => bytes,
        Err(_) => std::process::exit(2),
    };
    if tenebra::miner_auth::verify(&args[1], &challenge, &signature) {
        std::process::exit(0);
    }
    std::process::exit(1);
}
