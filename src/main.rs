#[macro_use]
mod utils;
mod logger;
mod models;
mod process_block;
mod state;
mod transactions;
use axum::http::StatusCode;
use axum_auto_routes::route;
use bitcoin::consensus::deserialize;
use bitcoin::Block;
use bitcoincore_rpc::RpcApi;
use models::blocks::BlockWithTransactions;
use mongodb::bson::doc;
use state::blocks::BlockStateTrait;
use state::init::AppStateTraitInitializer;
use state::transactions::TransactionBuilderStateTrait;
use state::AppState;
use state::WithState;
use std::env;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::sleep;
use transactions::build_and_run_multicall;
use utils::general::get_current_timestamp;
use utils::starknet::check_last_nonce_update_timestamp;

lazy_static::lazy_static! {
    pub static ref ROUTE_REGISTRY: Mutex<Vec<Box<dyn WithState>>> = Mutex::new(Vec::new());
    static ref MIN_CONFIRMATIONS: u64 = env::var("MIN_CONFIRMATIONS").expect("MIN_CONFIRMATIONS must be set").parse::<u64>().expect("MIN_CONFIRMATIONS must be a number");
}

#[tokio::main]
async fn main() {
    let shared_state: Arc<AppState> = AppState::load().await;
    shared_state
        .logger
        .async_info("starting utu bridge_auto_claim")
        .await;

    // Spawn a task to listen for ZMQ messages and add blocks into state
    let context = zmq::Context::new();
    let subscriber = context.socket(zmq::SUB).expect("Failed to create socket");
    subscriber
        .connect(&format!(
            "tcp://{}:{}",
            env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL must be set"),
            env::var("ZMQ_PORT").expect("ZMQ_PORT must be set")
        ))
        .expect("Failed to connect to socket");

    // Subscribe to topics
    // subscriber
    //     .set_subscribe(b"hashblock")
    //     .expect("Failed to subscribe to hashblock");

    subscriber
        .set_subscribe(b"rawblock")
        .expect("Failed to subscribe to hashblock");

    let zmq_state = shared_state.clone();
    let zmq_task = tokio::spawn(async move {
        loop {
            // Wait for a message from the socket
            match subscriber.recv_msg(0) {
                Ok(topic) => {
                    if topic.as_str() == Some("rawblock") {
                        let raw_block_msg =
                            subscriber.recv_msg(0).expect("Failed to receive raw block");

                        // Collect the bytes into a Vec<u8>, handling potential errors
                        let raw_block_data: Vec<u8> =
                            match raw_block_msg.bytes().collect::<Result<Vec<u8>, _>>() {
                                Ok(data) => data,
                                Err(e) => {
                                    zmq_state
                                        .logger
                                        .info(format!("Failed to collect raw block bytes: {}", e));
                                    return; // Exit the current iteration if there's an error
                                }
                            };

                        match deserialize::<Block>(&raw_block_data) {
                            Ok(block) => {
                                let block_hash = block.block_hash();
                                zmq_state
                                    .logger
                                    .info(format!("Received block hash: {}", block_hash));

                                zmq_state
                                    .with_blocks(|blocks| {
                                        blocks.add_block(block_hash);
                                    })
                                    .await;
                                zmq_state.notifier.notify_one();
                            }
                            Err(e) => {
                                // Handle deserialization errors
                                zmq_state
                                    .logger
                                    .info(format!("Failed to deserialize raw block: {}", e));
                            }
                        }
                    }

                    // if topic.as_str() == Some("hashblock") {
                    //     let block_hash_msg = subscriber
                    //         .recv_msg(0)
                    //         .expect("Failed to receive block hash");

                    //     let block_hash = match get_block_hash(block_hash_msg) {
                    //         Ok(block_hash) => block_hash,
                    //         Err(e) => {
                    //             zmq_state
                    //                 .logger
                    //                 .info(format!("Failed to get block hash: {}", e));
                    //             continue;
                    //         }
                    //     };
                    //     zmq_state.logger.info(format!("Received block hash: {}", block_hash));

                    //     zmq_state
                    //         .with_blocks(|blocks| {
                    //             blocks.add_block(block_hash);
                    //         })
                    //         .await;
                    //     zmq_state.notifier.notify_one();
                    // }
                }
                Err(e) => eprintln!("Failed to receive message: {}", e),
            }

            sleep(Duration::from_millis(1)).await;
        }
    });

    let block_state = shared_state.clone();
    let block_task = tokio::spawn(async move {
        loop {
            // Wait for changes in the blocks
            block_state.notifier.notified().await;

            if block_state
                .with_blocks_read(|blocks| blocks.has_blocks())
                .await
            {
                let block_hashes = block_state
                    .with_blocks_read(|blocks| blocks.get_blocks())
                    .await;

                for block_hash in block_hashes {
                    match block_state.bitcoin_provider.call::<BlockWithTransactions>(
                        "getblock",
                        &[serde_json::to_value(block_hash).unwrap(), 2.into()],
                    ) {
                        Ok(block) => {
                            if block.confirmations >= *MIN_CONFIRMATIONS {
                                block_state
                                    .logger
                                    .info(format!("Processing block: {}", block_hash));
                                if let Err(e) =
                                    process_block::process_block(&block_state, block_hash).await
                                {
                                    block_state
                                        .logger
                                        .severe(format!("Failed to process block: {}", e));
                                }
                                // We remove the block from the state
                                block_state
                                    .with_blocks(|blocks| {
                                        blocks.remove_block(block_hash);
                                    })
                                    .await;
                            }
                        }
                        Err(e) => eprintln!("Failed to get block: {}", e),
                    }
                }
            }
        }
    });

    // transaction loop task
    let tx_state = shared_state.clone();
    let tx_task = tokio::spawn(async move {
        loop {
            check_last_nonce_update_timestamp(&tx_state).await;

            let tx_count: usize = tx_state.transactions.get_tx_count().await;
            let last_update = tx_state.transactions.with_last_sent_read(|t| *t).await;
            let current_time = get_current_timestamp();

            if tx_count > 0 {
                let amount = if tx_count >= tx_state.transactions.max_queue_length {
                    tx_state.transactions.max_queue_length
                } else if last_update + tx_state.transactions.max_wait_time_ms < current_time {
                    tx_count
                } else {
                    0
                };

                tx_state
                    .logger
                    .info(format!("Attempting to send {} tx", amount));

                let tx_to_send = tx_state.transactions.empty_transactions_state(amount).await;
                let refresh_clone = tx_state.clone();
                build_and_run_multicall(&refresh_clone, tx_to_send).await;
            }

            // We wait 5 seconds before checking again
            sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // wait for both the zqm task, block_task to stop the program
    tokio::select! {
        _ = zmq_task => {},
        _ = block_task => {},
        _ = tx_task => {},
    }
}

#[route(get, "/")]
async fn root() -> (StatusCode, String) {
    (
        StatusCode::ACCEPTED,
        format!("server v{}", env!("CARGO_PKG_VERSION")),
    )
}
