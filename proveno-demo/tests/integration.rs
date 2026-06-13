use std::sync::Arc;
use std::time::Duration;

use proveno_demo::chain::ChainConfig;
use proveno_demo::{app, app_with_max_runs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn stub_chain_config() -> Arc<ChainConfig> {
    Arc::new(ChainConfig {
        rpc_url: "http://127.0.0.1:1".into(),
        chain_id: 31337,
        verifier_addr: "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap(),
        explorer_base: None,
    })
}

async fn spawn_app() -> u16 {
    spawn_router(app(stub_chain_config())).await
}

async fn spawn_router(router: axum::Router) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    // Tiny wait so the server is accepting connections before the test connects.
    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

async fn read_all(stream: &mut TcpStream) -> String {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    // The stub stream sends 7 events then drops the channel, which closes the
    // SSE body and the connection. Read until EOF.
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => panic!("timeout waiting for SSE stream to close"),
        }
    }
    String::from_utf8(buf).expect("response is utf8")
}

#[tokio::test]
async fn health_returns_ok() {
    let port = spawn_app().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_all(&mut stream).await;
    let (head, body) = response.split_once("\r\n\r\n").expect("response has body");
    assert!(head.starts_with("HTTP/1.1 200"), "head was: {head}");
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn run_emits_error_event_when_api_key_missing() {
    // Phase 2a drives the real pipeline. Without ANTHROPIC_API_KEY the runner
    // must emit a single `error` SSE event at the `generating_lua` stage and
    // then close the stream cleanly.
    // SAFETY: tests in this binary set/remove this env var serially.
    unsafe {
        std::env::remove_var("ANTHROPIC_API_KEY");
    }

    let port = spawn_app().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = br#"{"task":"What is 1 + 1?"}"#;
    let req = format!(
        "POST /run HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let response = read_all(&mut stream).await;
    let (head, body) = response.split_once("\r\n\r\n").expect("response has body");
    assert!(head.starts_with("HTTP/1.1 200"), "head was: {head}");
    assert!(
        head.to_lowercase()
            .contains("content-type: text/event-stream"),
        "expected SSE content-type, head was: {head}"
    );

    let data_payloads: Vec<&str> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .collect();

    // First event is generating_lua; then an error event before any LLM call.
    let stages: Vec<String> = data_payloads
        .iter()
        .map(|p| {
            let v: serde_json::Value = serde_json::from_str(p).expect("event is json");
            v["stage"].as_str().unwrap().to_string()
        })
        .collect();

    assert!(
        stages.first().map(String::as_str) == Some("generating_lua"),
        "expected generating_lua first, got {stages:?}",
    );
    assert!(
        stages.contains(&"error".to_string()),
        "expected an error event when ANTHROPIC_API_KEY is unset, got {stages:?}",
    );

    let error_payload = data_payloads
        .iter()
        .find_map(|p| {
            let v: serde_json::Value = serde_json::from_str(p).ok()?;
            if v["stage"] == "error" {
                Some(v)
            } else {
                None
            }
        })
        .expect("error event present");
    assert_eq!(error_payload["data"]["at_stage"], "generating_lua");
}

#[tokio::test]
async fn root_serves_static_index_html() {
    let port = spawn_app().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_all(&mut stream).await;
    let (head, body) = response.split_once("\r\n\r\n").expect("response has body");
    assert!(head.starts_with("HTTP/1.1 200"), "head was: {head}");
    assert!(
        head.to_lowercase().contains("content-type: text/html"),
        "expected text/html, head was: {head}",
    );
    assert!(
        body.contains("<title>proveno"),
        "expected index.html body, got: {}",
        &body.chars().take(200).collect::<String>(),
    );
}

#[tokio::test]
async fn options_run_returns_cors_headers() {
    let port = spawn_app().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(
            b"OPTIONS /run HTTP/1.1\r\n\
              Host: localhost\r\n\
              Origin: http://localhost:8080\r\n\
              Access-Control-Request-Method: POST\r\n\
              Access-Control-Request-Headers: content-type\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_all(&mut stream).await;
    let (head, _body) = response.split_once("\r\n\r\n").expect("response has body");
    let head_lower = head.to_lowercase();
    assert!(
        head_lower.contains("access-control-allow-origin"),
        "missing Access-Control-Allow-Origin, head was: {head}",
    );
    assert!(
        head_lower.contains("access-control-allow-methods"),
        "missing Access-Control-Allow-Methods, head was: {head}",
    );
}

#[tokio::test]
async fn run_returns_429_when_at_capacity() {
    // Drive saturation deterministically by building the router with zero permits.
    let port = spawn_router(app_with_max_runs(0, stub_chain_config())).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = br#"{"task":"saturated"}"#;
    let req = format!(
        "POST /run HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let response = read_all(&mut stream).await;
    let head = response
        .split_once("\r\n\r\n")
        .map(|(h, _)| h)
        .unwrap_or(&response);
    assert!(
        head.starts_with("HTTP/1.1 429"),
        "expected 429, head was: {head}",
    );
}
