use std::net::SocketAddr;
use std::sync::Arc;

use charming::{Chart, component::Axis, component::Legend, element::AxisType, series::Line};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};

pub struct Stats {
    pub request_count: u32,
    pub timeline: Vec<Duration>,
    pub started: SystemTime,
}

impl Stats {
    pub fn new() -> Stats {
        Stats {
            request_count: 0,
            timeline: vec![],
            started: SystemTime::now(),
        }
    }
}


struct FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite+ Unpin,
{
    outer_stream: IO,
    read_size: usize,
}

impl<IO> FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: IO) -> Self {
        Self {
            outer_stream: stream,
            read_size: 0,
        }
    }
}

impl<IO> AsyncWrite for FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let outer_stream = std::pin::Pin::new(&mut this.outer_stream);

        outer_stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        let outer_stream = std::pin::Pin::new(&mut this.outer_stream);

        outer_stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();


        println!("{} bytes", this.read_size);


        let outer_stream = std::pin::Pin::new(&mut this.outer_stream);
        outer_stream.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.outer_stream.is_write_vectored()
    }
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let outer_stream = std::pin::Pin::new(&mut this.outer_stream);
        outer_stream.poll_write_vectored(cx, bufs)
    }
}

impl<IO> AsyncRead for FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let outer_stream = std::pin::Pin::new(&mut this.outer_stream);
        let ret = outer_stream.poll_read(cx, buf);

        this.read_size += buf.filled().len();

        ret
    }
}

pub fn chart_stats(stats: Vec<(Stats, String)>, buckets: u32, duration: u64) -> Option<Chart> {
    let total_length = Duration::from_secs(duration);

    let mut names: Vec<String> = vec![];
    for cap in 1..=buckets {
        let top = (total_length / buckets) * cap;
        names.push(format!("{}ms", top.as_millis()));
    }

    let mut displays: Vec<(Vec<i32>, String)> = vec![];
    for stat in &stats {
        let mut display: Vec<i32> = vec![];
        for cap in 1..=buckets {
            let bottom = (total_length / buckets) * (cap - 1);
            let top = (total_length / buckets) * cap;

            let mut sum = 0;

            for &time in &stat.0.timeline {
                if bottom < time && time < top {
                    sum += 1;
                }
            }
            display.push(sum);
        }
        displays.push((display, stat.1.clone()));
    }

    let mut chart = Chart::new()
        .legend(Legend::new().data(stats.iter().map(|val| {val.1.clone()}).collect()))
        .x_axis(Axis::new().type_(AxisType::Category).data(names))
        .y_axis(Axis::new().type_(AxisType::Value));

    for display in displays {
        chart = chart.series(Line::new().name(display.1).stack("Total").data(display.0));
    }
    return Some(chart);
}

#[derive(PartialEq)]
pub enum Messages {
    ClientStart,
    ClientEnd,
}

pub async fn run_server(
    tx: Sender<Messages>,
    duration: u64,
) -> Result<Stats, Box<dyn std::error::Error>> {
    let mut stats = Stats::new();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let certs =
        CertificateDer::pem_file_iter("./certs/cert.pem")?
            .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(
        "./certs/cert.key.pem",
    )?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await?;

    println!("Running on localhost:3000");
    tx.send(Messages::ClientStart).expect("couldnt send");

    let mut done = false;
    while !done {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let now = SystemTime::now();
        let since_start = now
            .duration_since(stats.started)
            .expect("time should go forward");

        stats.timeline.push(since_start);
        stats.request_count += 1;

        if since_start > Duration::from_secs(duration) {
            done = true;
        }

        tokio::task::spawn(async move {
            let mut tls_stream = acceptor
                .accept(stream)
                .await
                .ok()
                .expect("failed to accept tls");

            let response = "OK!";
            if let Err(error) = tls_stream.write(response.as_bytes()).await {
                println!("TLS Error: {}", error)
            }

            tls_stream.shutdown().await.expect("failed to shutdown");
        });
    }
    tx.send(Messages::ClientEnd).expect("couldnt send");
    Ok(stats)
}
