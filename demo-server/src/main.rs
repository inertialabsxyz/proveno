use luai_demo_server::app;

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("bind 0.0.0.0:3001");
    axum::serve(listener, app()).await.expect("axum serve");
}
