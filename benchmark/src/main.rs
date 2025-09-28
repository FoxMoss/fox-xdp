use std::{ops::Deref, os::unix::process::CommandExt, process::Command, thread};
use std::panic;
mod client;
mod server;
use charming::{ImageFormat, ImageRenderer};
use std::sync::mpsc;
use tokio::runtime::Runtime;

use crate::server::{Filter, chart_stats};

fn drop_test(duration: u64, buckets: u32) -> client::Stats {
    let (tx, rx) = mpsc::channel::<server::Messages>();
    let server_thread = thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            server::run_server(tx, duration, Some(Filter::DropAll))
                .await
                .expect("Server failed")
        })
    });

    let client_thread = thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            client::run_drop_client(rx, duration, buckets)
                .await
                .expect("Client failed")
        })
    });

    server_thread.join().unwrap();
    let stats = client_thread.join().unwrap();
    let stats = stats.lock().unwrap();

    return stats.deref().clone();
}

fn test(duration: u64, filter: Option<Filter>, buckets: u32) -> client::Stats {
    let (tx, rx) = mpsc::channel::<server::Messages>();
    let server_thread = thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            server::run_server(tx, duration, filter)
                .await
                .expect("Server failed")
        })
    });

    let client_thread = thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async move {
            client::run_client(rx, duration, buckets)
                .await
                .expect("Client failed")
        })
    });

    server_thread.join().unwrap();
    let stats = client_thread.join().unwrap();
    let stats = stats.lock().unwrap();

    return stats.deref().clone();
}

fn main() {
    let buckets = 10;
    let duration = 10;

    let sha_filter = test(duration, Some(Filter::Sha256Hash), buckets);

    let jenkins_filter = test(duration, Some(Filter::JenkinsHash), buckets);

    let mut sudo_cache_command = Command::new("sudo");
    sudo_cache_command.args(["echo", "Starting!"]);
    sudo_cache_command.output().expect("sudo cache fail");

    let mut fox_filter_command = Command::new("sudo");
    fox_filter_command.args([
        "../build/fox-filter",
        "../build/fox.conf",
        "lo",
        "../build/fox.bpf",
    ]);
    let mut child_filter = fox_filter_command.spawn().expect("failed to spawn");
    let xdp = test(duration, None, buckets);
    child_filter.kill().expect("failed to kill");

    let no_filter = test(duration, None, buckets);

    let slowdown_filter = test(duration, Some(Filter::OneMillisecondsSlowDown), buckets);

    let chart = chart_stats(
        vec![
            (no_filter, "No filter".to_string()),
            (slowdown_filter, "Delay by 1ms".to_string()),
            (
                jenkins_filter,
                "Calculating Jenkins hash in userspace".to_string(),
            ),
            (xdp, "Calculating Jenkins hash in XDP".to_string()),
            (sha_filter, "Calculating SHA hash in userspace".to_string()),
        ],
        buckets,
        duration,
    )
    .expect("chart failed");

    let mut renderer = ImageRenderer::new(1000, 800).theme(charming::theme::Theme::Custom(
        "chalk",
        include_str!("../echarts_theme.js"),
    ));
    renderer
        .save_format(ImageFormat::Png, &chart, "dist/chart1.png")
        .expect("chart rendering failed");

    //
    // let mut sudo_cache_command = Command::new("sudo");
    //
    // sudo_cache_command.args(["echo", "Starting!"]);
    // sudo_cache_command.output().expect("sudo cache fail");
    //
    // let mut fox_filter_command = Command::new("sudo");
    // fox_filter_command.args([
    //     "../build/fox-filter",
    //     "../build/blacklist.conf",
    //     "lo",
    //     "../build/fox.bpf",
    // ]);
    // let mut child_filter = fox_filter_command.spawn().expect("failed to spawn");
    // let xdp_drop_test = drop_test(duration, buckets);
    // child_filter.kill().expect("failed to kill");
    //
    // println!("done!");
    //
    // let chart = chart_stats(
    //     vec![
    //         (normal_drop_test, "Dropping in userspace".to_string()),
    //         (xdp_drop_test, "Dropping with XDP".to_string()),
    //     ],
    //     buckets,
    //     duration,
    // )
    // .expect("chart failed");
    //
    // let mut renderer = ImageRenderer::new(1000, 800).theme(charming::theme::Theme::Custom(
    //     "chalk",
    //     include_str!("../echarts_theme.js"),
    // ));
    // renderer
    //     .save_format(ImageFormat::Png, &chart, "dist/chart2.png")
    //     .expect("chart rendering failed");
}
