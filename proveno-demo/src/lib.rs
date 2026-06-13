pub mod chain;
pub mod events;
pub mod public_inputs;
pub mod runner;

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

use chain::ChainConfig;
use events::DemoEvent;

const MAX_CONCURRENT_RUNS: usize = 5;

#[derive(Clone)]
struct AppState {
    run_semaphore: Arc<Semaphore>,
    chain_config: Arc<ChainConfig>,
}

#[derive(Deserialize)]
struct RunRequest {
    task: String,
}

pub fn app(chain_config: Arc<ChainConfig>) -> Router {
    app_with_max_runs(MAX_CONCURRENT_RUNS, chain_config)
}

#[doc(hidden)]
pub fn app_with_max_runs(max_runs: usize, chain_config: Arc<ChainConfig>) -> Router {
    let state = AppState {
        run_semaphore: Arc::new(Semaphore::new(max_runs)),
        chain_config,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .route("/health", get(health))
        .route("/run", post(run))
        .fallback_service(ServeDir::new("static"))
        .with_state(state)
        .layer(cors)
}

async fn health() -> &'static str {
    "ok"
}

async fn run(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let permit = state
        .run_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;

    let (tx, rx) = mpsc::channel::<DemoEvent>(32);
    let chain_config = state.chain_config.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        runner::run_pipeline(req.task, tx, chain_config);
    });

    let stream = ReceiverStream::new(rx).map(|ev| {
        let payload = serde_json::to_string(&ev).expect("serialize DemoEvent");
        Ok(Event::default().data(payload))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
