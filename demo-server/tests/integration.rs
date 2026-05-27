use std::time::Duration;

use luai_demo_server::app;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app()).await.unwrap();
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
async fn run_streams_expected_sse_sequence() {
    let port = spawn_app().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = br#"{"task":"Did ETH close above $3000?"}"#;
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

    // Reassemble the chunked body. axum's SSE response uses HTTP/1.1
    // chunked transfer encoding, so the raw body is `<hex>\r\n<chunk>\r\n...`.
    // For this stub each chunk is one full SSE event so we can just collect
    // every line that starts with `data: `.
    let data_payloads: Vec<&str> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .collect();

    assert_eq!(
        data_payloads.len(),
        7,
        "expected 7 SSE events, got {}: {:#?}",
        data_payloads.len(),
        data_payloads
    );

    let stages: Vec<String> = data_payloads
        .iter()
        .map(|p| {
            let v: serde_json::Value = serde_json::from_str(p).expect("event is json");
            v["stage"].as_str().unwrap().to_string()
        })
        .collect();

    assert_eq!(
        stages,
        vec![
            "generating_lua",
            "lua_ready",
            "compiling",
            "executing",
            "tool_call",
            "proving",
            "complete",
        ],
    );

    let first: serde_json::Value = serde_json::from_str(data_payloads[0]).unwrap();
    assert_eq!(first["data"]["prompt"], "Did ETH close above $3000?");

    let last: serde_json::Value = serde_json::from_str(data_payloads[6]).unwrap();
    assert_eq!(last["data"]["result"], serde_json::Value::Bool(true));
    let hashes = &last["data"]["hashes"];
    for field in [
        "program_hash",
        "input_hash",
        "tool_responses_hash",
        "output_hash",
        "tls_attestation_hash",
        "policy_hash",
    ] {
        assert!(
            hashes[field].is_string(),
            "hashes.{field} missing or not a string"
        );
    }
}
