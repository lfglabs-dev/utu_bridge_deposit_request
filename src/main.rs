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
use state::blocks::BlockStateTrait;
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

                                let is_included = zmq_state
                                    .with_blocks_read(|blocks| {
                                        let block_hashes = blocks.get_blocks();
                                        block_hashes.contains(&block_hash)
                                    })
                                    .await;

                                if is_included {
                                    zmq_state
                                        .logger
                                        .info(format!("Block already exists: {}", block_hash));
                                    continue;
                                }

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
                                if let Err(e) = process_block::process_block(
                                    &block_state,
                                    block_hash,
                                    block.height,
                                    true,
                                )
                                .await
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
