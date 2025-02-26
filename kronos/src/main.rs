use anyhow::{Context, Ok, Result};
// use helpers::k8s_helpers::{kubernetes, runtime};
use log::{debug, info, warn};
use tokio::signal;
use tokio::sync::mpsc;
mod cache_manager;
mod ebpf_manager;
mod k8s_manager;
// mod kronos_daemon;
// mod kwatch;
mod k_daemon;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Load and attach the eBPF program
    info!("Loading BPF programs...");
    // kronos_daemon::start_daemon().await;
    // k_daemon::start_daemon().await;
    ebpf_manager::bpfloader::load_bpf_programs();

    Ok(())
}
