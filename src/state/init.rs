use std::{env, sync::Arc};

use bitcoin::Network;
use bitcoincore_rpc::Auth;
use mongodb::options::ClientOptions;
use utu_bridge_types::bitcoin::BitcoinAddress;

use crate::{logger::Logger, state::AppState};

pub trait AppStateTraitInitializer {
    async fn load() -> Arc<Self>;
}

impl AppStateTraitInitializer for AppState {
    async fn load() -> Arc<Self> {
        let logger = Logger::new();
        let db = mongodb::Client::with_options(
            ClientOptions::parse(
                env::var("MONGODB_CONNECTION_STRING")
                    .expect("MONGODB_CONNECTION_STRING must be set"),
            )
            .await
            .unwrap(),
        )
        .unwrap()
        .database(&env::var("MONGODB_NAME").expect("MONGODB_NAME must be set"));

        let bitcoin_rpc_user = env::var("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER must be set");
        let bitcoin_rpc_password =
            env::var("BITCOIN_RPC_PASSWORD").expect("BITCOIN_RPC_PASSWORD must be set");
        let bitcoin_auth = if bitcoin_rpc_user.is_empty() || bitcoin_rpc_password.is_empty() {
            Auth::None
        } else {
            Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password)
        };

        let bitcoin_provider = bitcoincore_rpc::Client::new(
            &env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL must be set"),
            bitcoin_auth,
        )
        .unwrap();

        // Load blacklisted addresses
        let blacklisted_deposit_addr_len = env::var("BLACKLISTED_DEPOSIT_ADDR_LEN")
            .expect("BLACKLISTED_DEPOSIT_ADDR_LEN must be set")
            .parse::<u64>()
            .expect("BLACKLISTED_DEPOSIT_ADDR_LEN must be a valid u64");
        let mut blacklisted_deposit_addr: Vec<BitcoinAddress> = Vec::new();
        for i in 0..blacklisted_deposit_addr_len {
            blacklisted_deposit_addr.push(
                BitcoinAddress::new(
                    &env::var(format!("BLACKLISTED_DEPOSIT_ADDR_{}", i))
                        .unwrap_or_else(|_| panic!("BLACKLISTED_DEPOSIT_ADDR_{} must be set", i)),
                    Network::Bitcoin,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "BLACKLISTED_DEPOSIT_ADDR_{} is not a valid bitcoin address",
                        i
                    )
                }),
            );
        }

        Arc::new_cyclic(|_| AppState {
            logger,
            db,
            bitcoin_provider,
            blacklisted_deposit_addr,
        })
    }
}
