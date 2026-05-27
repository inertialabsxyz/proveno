pub mod events;

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};

use events::{DemoEvent, ProofHashes};

#[derive(Deserialize)]
struct RunRequest {
    task: String,
}

pub fn app() -> Router {
    // Phase 3 stub: static file serving
    // .nest_service("/static", ServeDir::new("demo-server/static"))
    Router::new()
        .route("/health", get(health))
        .route("/", get(index))
        .route("/run", post(run))
}

async fn health() -> &'static str {
    "ok"
}

async fn index() -> impl IntoResponse {
    // Phase 3 will replace this with static file serving.
    "ok"
}

async fn run(Json(req): Json<RunRequest>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel::<DemoEvent>(32);
    tokio::spawn(stub_pipeline(req.task, tx));

    let stream = ReceiverStream::new(rx).map(|ev| {
        let payload = serde_json::to_string(&ev).expect("serialize DemoEvent");
        Ok(Event::default().data(payload))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn stub_pipeline(task: String, tx: mpsc::Sender<DemoEvent>) {
    let step = Duration::from_millis(25);
    let events = [
        DemoEvent::GeneratingLua { prompt: task },
        DemoEvent::LuaReady {
            lua: "return 1 + 1".to_string(),
        },
        DemoEvent::Compiling,
        DemoEvent::Executing,
        DemoEvent::ToolCall {
            name: "http_get".to_string(),
            args: "{\"url\":\"https://example.com\"}".to_string(),
            response: "{\"status\":200,\"body\":\"...\"}".to_string(),
        },
        DemoEvent::Proving,
        DemoEvent::Complete {
            result: serde_json::Value::Bool(true),
            hashes: ProofHashes {
                program_hash: "stub-hash-program".to_string(),
                input_hash: "stub-hash-input".to_string(),
                tool_responses_hash: "stub-hash-tool-responses".to_string(),
                output_hash: "stub-hash-output".to_string(),
                tls_attestation_hash: "stub-hash-tls-attestation".to_string(),
                policy_hash: "stub-hash-policy".to_string(),
            },
        },
    ];

    for ev in events {
        if tx.send(ev).await.is_err() {
            return;
        }
        tokio::time::sleep(step).await;
    }
}
