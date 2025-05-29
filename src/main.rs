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
use mongodb::bson::doc;
use process_block::get_block_from_rpc;
use process_block::process_output;
use process_block::wait_for_block_confirmation;
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
use utils::runes::get_supported_runes_vec;
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
                let mut session = match processor.db.client().start_session().await {
                    Ok(session) => session,
                    Err(_) => {
                        processor.logger.severe(format!(
                            "[{}] Database error: unable to start session when processing block",
                            block_hash
                        ));
                        return;
                    }
                };

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

                let (supported_runes, runes_mapping) =
                    match get_supported_runes_vec(&processor).await {
                        Ok(runes) => runes,
                        Err(e) => {
                            processor.logger.warning(format!(
                                "[{}] Failed to get supported runes: {}",
                                block_hash, e
                            ));
                            return;
                        }
                    };

                let block_from_rpc =
                    match get_block_from_rpc(&processor, block_hash_value.clone()).await {
                        Ok(block_from_rpc) => block_from_rpc,
                        Err(e) => {
                            processor
                                .logger
                                .warning(format!("Failed to get block from RPC: {}", e));
                            return; // Stop task for this block
                        }
                    };

                let outputs_to_process = match process_block::parse_block(
                    &processor,
                    &mut session,
                    block_from_rpc.height,
                    block.clone(),
                    supported_runes,
                    // true,
                )
                .await
                {
                    Ok(outputs) => outputs,
                    Err(e) => {
                        processor
                            .logger
                            .warning(format!("[{}] Failed to parse block: {}", block_hash, e));
                        return;
                    }
                };

                if outputs_to_process.is_empty() {
                    processor.logger.info(format!(
                        "[{}] No outputs found to process. Stopping task.",
                        block_from_rpc.height
                    ));
                    return;
                }

                processor.logger.info(format!(
                    "[{}] {} outputs found to process:\n {}",
                    block_from_rpc.height,
                    outputs_to_process.len(),
                    outputs_to_process
                        .iter()
                        .map(|o| format!("{}:{}", o.txid, o.output_index))
                        .collect::<Vec<String>>()
                        .join(", ")
                ));

                processor.logger.info(format!(
                    "[{}] Waiting for block to be confirmed",
                    block_from_rpc.height
                ));

                // Waiting for the block to be confirmed
                if wait_for_block_confirmation(&processor, block_hash_value.clone())
                    .await
                    .is_err()
                {
                    processor.logger.severe(format!(
                        "[{}] Block was not integrated (confirmations = -1), stopping task",
                        block_from_rpc.height
                    ));
                    return;
                } else {
                    processor.logger.info(format!(
                        "[{}] Block was integrated. Processing outputs.",
                        block_from_rpc.height
                    ));
                }

                // process the outputs
                for output in outputs_to_process {
                    if let Err(e) =
                        process_output(&processor, &mut session, output, block_hash, &runes_mapping)
                            .await
                    {
                        processor
                            .logger
                            .severe(format!("[{}] {}", block_from_rpc.height, e));
                    }
                }

                processor.logger.info(format!(
                    "[{}] Finished processing block. Stopping task.",
                    block_from_rpc.height
                ));
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
