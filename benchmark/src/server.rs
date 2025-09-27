use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::sleep;
use sha256::{digest, try_digest};
use charming::{Chart, component::Axis, component::Legend, element::AxisType, series::Line};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite;
use tokio_rustls::{TlsAcceptor, rustls};

use crate::client::Stats;

// uint32_t calculate_hash(uint16_t *data, size_t len) {
//   uint32_t hash = 0;
//   uint16_t lowest = 0;
//   for (size_t i = 0; i < len; i++) {
//     uint16_t lowest_high = UINT16_MAX;
//     for (size_t j = 0; j < len; j++) {
//       if (data[j] < lowest_high && data[j] > lowest) {
//         lowest_high = data[j];
//       }
//     }
//     lowest = lowest_high;
//     hash += lowest;
//     hash += hash << 10;
//     hash ^= hash >> 6;
//   }
//   hash += hash << 3;
//   hash ^= hash >> 11;
//   hash += hash << 15;
//   return hash;
// }

fn u8_vec_to_u16_vec(bytes: Vec<u8>) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
        .collect()
}

pub fn calculate_hash(buf: Vec<u16>) -> u32 {
    let mut hash: u32 = 0;
    let mut lowest: u16 = 0;
    for _ in &buf {
        let mut lowest_high = std::u16::MAX;
        for j in &buf {
            if *j < lowest_high && *j > lowest {
                lowest_high = *j;
            }
        }
        lowest = lowest_high;
        hash = hash.wrapping_add(u32::from(lowest));
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);

    hash
}

#[derive(Clone)]
pub enum Filter {
    OneMillisecondsSlowDown,
    JenkinsHash,
    Sha256Hash,
    None,
}

struct FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    outer_stream: IO,
    read_size: usize,
    filter: Filter,
    data: Vec<u8>,
    hash: Option<u32>,
}

impl<IO> FingerprintMiddleware<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: IO, filter: Filter) -> Self {
        Self {
            outer_stream: stream,
            read_size: 0,
            filter: filter,
            data: vec![],
            hash: None,
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

        match this.filter {
            Filter::OneMillisecondsSlowDown => {
                sleep(Duration::from_millis(1));
            }
            Filter::JenkinsHash => {
                if this.hash.is_none() {
                    this.data.append(&mut buf.filled().to_vec());
                    if this.data.len() > 4 {
                        let total_len = u16::from_be_bytes(
                            this.data[3..=4].try_into().expect("failed to parse size"),
                        );

                        // we have all of our data!
                        if this.data.len() >= total_len.into() {
                            let mut cursor = 1 + 2 + 2 + 1 + 3 + 2 + 32 + 1 + 32; // cipher suites cursor
                            let cipher_length: usize = u16::from_be_bytes(
                                this.data[cursor..=(cursor + 1)]
                                    .try_into()
                                    .expect("failed to parse uint"),
                            )
                            .into();
                            cursor += 2;
                            let ciphers: Vec<u8> =
                                this.data[cursor..=(cursor + cipher_length)].to_vec();
                            let mut ciphers_16 = u8_vec_to_u16_vec(ciphers);

                            ciphers_16.sort();

                            this.hash = Some(calculate_hash(ciphers_16));
                        }
                    }
                }
            }
            Filter::Sha256Hash => {
                this.data.append(&mut buf.filled().to_vec());
                if this.data.len() > 4 {
                    let total_len = u16::from_be_bytes(
                        this.data[3..=4].try_into().expect("failed to parse size"),
                    );

                    // we have all of our data!
                    if this.data.len() >= total_len.into() {
                        let mut cursor = 1 + 2 + 2 + 1 + 3 + 2 + 32 + 1 + 32; // cipher suites cursor
                        let cipher_length: usize = u16::from_be_bytes(
                            this.data[cursor..=(cursor + 1)]
                                .try_into()
                                .expect("failed to parse uint"),
                        )
                        .into();
                        cursor += 2;
                        let mut ciphers: Vec<u8> =
                            this.data[cursor..=(cursor + cipher_length)].to_vec();

                        ciphers.sort();

                        digest(ciphers);
                    }
                }
            }
            Filter::None => {}
        }

        this.read_size += buf.filled().len();

        ret
    }
}

pub fn chart_stats(stats: Vec<(Stats, String)>, buckets: u32, duration: u64) -> Option<Chart> {
    let total_length = Duration::from_secs(duration);

    let mut names: Vec<String> = vec![];
    let mut line_names: Vec<String> = vec![];
    for cap in 1..=buckets {
        let top = (total_length / buckets) * cap;
        names.push(format!("{}ms", top.as_millis()));
    }

    let mut displays: Vec<(Vec<i32>, String)> = vec![];
    for stat in &stats {
        line_names.push(stat.1.clone());
        displays.push((stat.0.timeline.clone().into_iter().map(|val| val.try_into().unwrap()).collect(), stat.1.clone()));
    }

    let mut chart = Chart::new()
        .legend(Legend::new().data(line_names))
        .x_axis(Axis::new().type_(AxisType::Category).data(names))
        .y_axis(Axis::new().type_(AxisType::Value));

    for display in displays {
        chart = chart.series(Line::new().name(display.1).data(display.0));
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
    filter: Option<Filter>,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = SystemTime::now();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let certs =
        CertificateDer::pem_file_iter("./certs/cert.pem")?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file("./certs/cert.key.pem")?;

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

        {
            let now = SystemTime::now();
            let since_start = now.duration_since(started).expect("time should go forward");

            if since_start > Duration::from_secs(duration) {
                done = true;
            }
        }

        let filter_clone = filter.clone();

        tokio::task::spawn(async move {
            let middleware =
                FingerprintMiddleware::new(stream, filter_clone.unwrap_or(Filter::None));
            let mut tls_stream = acceptor
                .accept(middleware)
                .await
                .ok()
                .expect("failed to accept tls");

            let mut buf: Vec<u8> = vec![0; 1024];
            if let Err(error) = tls_stream.read(&mut buf).await {
                println!("TLS Error: {}", error)
            }

            if let Err(error) = tls_stream.write(&mut buf).await {
                println!("TLS Error: {}", error)
            }

            tls_stream.shutdown().await.expect("failed to shutdown");
        });
    }
    tx.send(Messages::ClientEnd).expect("couldnt send");
    Ok(())
}
