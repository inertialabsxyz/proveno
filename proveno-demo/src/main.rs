use std::sync::Arc;

use proveno_demo::{app, chain};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let (chain_config, anvil_handle) = match chain::init_chain().await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("error: failed to initialize chain layer: {e}");
            std::process::exit(1);
        }
    };

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("bind 0.0.0.0:3001");

    eprintln!("proveno demo server listening on http://localhost:3001");
    let mode = if anvil_handle.is_some() {
        "managed-anvil"
    } else {
        "external"
    };
    match (mode, &chain_config.explorer_base) {
        ("managed-anvil", _) => eprintln!(
            "chain mode: managed-anvil (chain_id={}, verifier={})",
            chain_config.chain_id, chain_config.verifier_addr
        ),
        ("external", Some(explorer)) => eprintln!(
            "chain mode: external (chain_id={}, verifier={}, explorer={})",
            chain_config.chain_id, chain_config.verifier_addr, explorer
        ),
        ("external", None) => eprintln!(
            "chain mode: external (chain_id={}, verifier={})",
            chain_config.chain_id, chain_config.verifier_addr
        ),
        _ => {}
    }

    let chain_config = Arc::new(chain_config);

    axum::serve(listener, app(chain_config))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("axum serve");

    // Anvil child (if any) is killed by AnvilHandle::drop here.
    drop(anvil_handle);
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl_c handler");
}
