use std::{os::unix::process::CommandExt, process::Command, thread};

mod client;
mod server;
use charming::{ImageFormat, ImageRenderer};
use std::sync::mpsc;
use tokio::runtime::Runtime;

use crate::server::chart_stats;

fn test(duration: u64) -> server::Stats {
    let (tx, rx) = mpsc::channel::<server::Messages>();
    let server_thread = thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            server::run_server(tx, duration)
                .await
                .expect("Server failed")
        })
    });

    let client_thread = thread::spawn(|| {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            client::run_client(rx).await.expect("Client failed");
        })
    });

    let stats = server_thread.join().unwrap();
    client_thread.join().unwrap_or_default();
    return stats;
}

fn main() {
    let mut sudo_cache_command = Command::new("sudo");
    sudo_cache_command.args(["echo", "Starting!"]);
    sudo_cache_command.output().expect("sudo cache fail");

    let buckets = 40;
    let duration = 10;

    let mut fox_filter_command = Command::new("sudo");
    fox_filter_command.args([
        "../build/fox-filter",
        "../build/fox.conf",
        "lo",
        "../build/fox.bpf",
    ]);
    let mut child_filter = fox_filter_command.spawn().expect("failed to spawn");
    let xdp = test(duration);
    child_filter.kill().expect("failed to kill");

    let no_filter = test(duration);

    let chart = chart_stats(
        vec![
            (no_filter, "No filter".to_string()),
            (xdp, "Calculating Jenkins hash in XDP".to_string()),
        ],
        buckets,
        duration,
    )
    .expect("chart failed");

    let mut renderer = ImageRenderer::new(1000, 800).theme(charming::theme::Theme::Vintage);
    renderer
        .save_format(ImageFormat::Png, &chart, "dist/chart1.png")
        .expect("chart rendering failed");
}
