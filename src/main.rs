#![forbid(unsafe_code)]

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error, warn};

mod config;
mod transport;
mod smb2;
mod server;
mod auth;
mod vfs;
mod error;
mod signing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .or_else(|| {
            std::env::args()
                .position(|a| a == "--config")
                .and_then(|i| std::env::args().nth(i + 1))
        })
        .unwrap_or_else(|| "config.toml".to_string());

    let config = config::load_config(&config_path)?;

    // Validate share paths exist
    for share in &config.shares {
        if !share.path.exists() {
            warn!(
                "Share '{}' path does not exist: {}",
                share.name,
                share.path.display()
            );
        }
    }

    let server_state = Arc::new(server::ServerState::new(config.clone()));
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("SMB2 server listening on {}", addr);
    info!(
        "Shares: {}",
        config
            .shares
            .iter()
            .map(|s| format!("{}={}", s.name, s.path.display()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Handle graceful shutdown
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        info!("Connection from {}", peer);
                        let state = server_state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server::handle_connection(stream, state).await {
                                error!("Connection from {} error: {:?}", peer, e);
                            }
                            info!("Connection from {} closed", peer);
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {:?}", e);
                    }
                }
            }
            _ = &mut shutdown => {
                info!("Shutting down");
                break;
            }
        }
    }

    Ok(())
}
