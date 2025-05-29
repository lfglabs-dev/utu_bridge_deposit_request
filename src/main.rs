#[macro_use]
mod utils;
mod logger;
mod models;
mod process_block;
mod server;
mod state;
use axum::http::StatusCode;
use axum::Extension;
use axum::Router;
use axum_auto_routes::route;
use bitcoin::consensus::deserialize;
use bitcoin::Block;
use bitcoincore_rpc::RpcApi;
use models::blocks::BlockWithTransactions;
use mongodb::bson::doc;
use state::init::AppStateTraitInitializer;
use state::AppState;
use state::WithState;
use std::env;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::sleep;
use tower_http::cors;
use tower_http::cors::CorsLayer;
use utils::runes::log_supported_runes;

lazy_static::lazy_static! {
    pub static ref ROUTE_REGISTRY: Mutex<Vec<Box<dyn WithState>>> = Mutex::new(Vec::new());
    static ref MIN_CONFIRMATIONS: i64 = env::var("MIN_CONFIRMATIONS").expect("MIN_CONFIRMATIONS must be set").parse::<i64>().expect("MIN_CONFIRMATIONS must be a number");
}

#[tokio::main]
async fn main() {
    let shared_state: Arc<AppState> = AppState::load().await;
    shared_state
        .logger
        .async_info("starting utu deposit_request")
        .await;

    // setup http server
    let cors = CorsLayer::new()
        .allow_headers(cors::Any)
        .allow_origin(cors::Any);
    let app = ROUTE_REGISTRY
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .fold(Router::new(), |acc, r| {
            acc.merge(r.to_router(shared_state.clone()))
        })
        .layer(cors)
        .layer(Extension(shared_state.clone()));

    let server_port = env::var("SERVER_PORT")
        .expect("SERVER_PORT must be set")
        .parse::<u16>()
        .expect("invalid SERVER_PORT format");
    let addr = SocketAddr::from(([0, 0, 0, 0], server_port));

    // spawn the server task
    let server_task = tokio::spawn(async move {
        axum::Server::bind(&addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    shared_state
        .logger
        .async_info(format!(
            "server: listening on http://0.0.0.0:{}",
            server_port
        ))
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

    shared_state
        .logger
        .info("Listening to separate deposit requests from Bitcoin to Starknet.");
    let _ = log_supported_runes(&shared_state).await;

    subscriber
        .set_subscribe(b"rawblock")
        .expect("Failed to subscribe to hashblock");

    let (block_sender, mut block_receiver) = tokio::sync::mpsc::channel::<Block>(100); // Buffer size of 100

    let zmq_state = shared_state.clone();
    let zmq_sender = block_sender.clone();
    let zmq_task = tokio::spawn(async move {
        loop {
            // Wait for a message from the socket
            match subscriber.recv_msg(0) {
                Ok(topic) => {
                    if topic.as_str() == Some("rawblock") {
                        zmq_state.logger.info("Received raw block");
                        let raw_block_msg =
                            subscriber.recv_msg(0).expect("Failed to receive raw block");

                        // Collect the bytes into a Vec<u8>, handling potential errors
                        let raw_block_data: Vec<u8> =
                            match raw_block_msg.bytes().collect::<Result<Vec<u8>, _>>() {
                                Ok(data) => data,
                                Err(e) => {
                                    zmq_state.logger.warning(format!(
                                        "Failed to collect raw block bytes: {}",
                                        e
                                    ));
                                    return; // Exit the current iteration if there's an error
                                }
                            };

                        zmq_state.logger.info("Deserializing raw block");

                        match deserialize::<Block>(&raw_block_data) {
                            Ok(block) => {
                                let block_hash = block.block_hash();
                                let block_height = if let Ok(height) = block.bip34_block_height() {
                                    height.to_string()
                                } else {
                                    "unknown".to_string()
                                };
                                zmq_state.logger.info(format!(
                                    "Received block (height: {}) | Hash: {}",
                                    block_height, block_hash
                                ));

                                if let Err(e) = zmq_sender.send(block).await {
                                    zmq_state.logger.warning(format!(
                                        "Failed to send block to processor: {}",
                                        e
                                    ));
                                }
                            }
                            Err(e) => {
                                // Handle deserialization errors
                                zmq_state
                                    .logger
                                    .warning(format!("Failed to deserialize raw block: {}", e));
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to receive message: {}", e),
            }

            sleep(Duration::from_millis(1)).await;
        }
    });

    let block_state = shared_state.clone();
    let block_task = tokio::spawn(async move {
        while let Some(block) = block_receiver.recv().await {
            block_state.logger.info(format!(
                "[{}] Notification received, processing block",
                block.block_hash()
            ));

            let block_hash = block.block_hash();
            let processor = block_state.clone();

            tokio::spawn(async move {
                let mut attempts = 0;
                let max_attempts = 5;

                // Wait for confirmations before processing
                loop {
                    let block_hash_value = match serde_json::to_value(block_hash) {
                        Ok(value) => value,
                        Err(e) => {
                            processor.logger.warning(format!(
                                "[{}] Failed to serialize block hash: {}",
                                block_hash, e
                            ));
                            return;
                        }
                    };

                    match processor
                        .bitcoin_provider
                        .call::<BlockWithTransactions>("getblock", &[block_hash_value, 2.into()])
                    {
                        Ok(block_from_rpc) => {
                            attempts = 0;
                            if block_from_rpc.confirmations >= *MIN_CONFIRMATIONS {
                                processor.logger.info(format!(
                                    "Processing block (height: {}) | Hash: {}",
                                    block_from_rpc.height, block_hash
                                ));

                                if let Err(e) = process_block::process_block(
                                    &processor,
                                    block_hash,
                                    block,
                                    true,
                                    block_from_rpc.height,
                                )
                                .await
                                {
                                    processor.logger.severe(format!(
                                        "[{}] Error in process_block: {}",
                                        block_hash, e
                                    ));
                                }
                                return; // Done processing this block
                            } else if block_from_rpc.confirmations == -1 {
                                // block not included in the main chain
                                processor.logger.warning(format!(
                                    "[{}] Block was not integrated (confirmations = -1), stopping task",
                                    block_hash
                                ));
                                return; // Stop task for this block
                            } else {
                                sleep(Duration::from_secs(60)).await;
                            }
                        }
                        Err(e) => {
                            processor.logger.warning(format!(
                                "[{}] Failed to get block from RPC: {}, retrying in 1 minute",
                                block_hash, e
                            ));
                            attempts += 1;
                            if attempts > max_attempts {
                                processor.logger.severe(format!(
                                    "[{}] Failed to get block from RPC: {}, stopping task",
                                    block_hash, e
                                ));
                                return; // Stop task for this block
                            }
                            sleep(Duration::from_secs(60)).await;
                        }
                    }
                }
            });
        }
    });

    // wait for both the zqm task, block_task to stop the program
    tokio::select! {
        _ = server_task => {},
        _ = zmq_task => {},
        _ = block_task => {},
    }
}

#[route(get, "/")]
async fn root() -> (StatusCode, String) {
    (
        StatusCode::ACCEPTED,
        format!("server v{}", env!("CARGO_PKG_VERSION")),
    )
}
