use std::net::SocketAddr;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsConnector, rustls};

use crate::server::Messages;

static PERMITS: Semaphore = Semaphore::const_new(500);

#[derive(Clone)]
pub struct Stats {
    pub request_count: u32,
    pub timeline: Vec<u64>,
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

pub async fn run_client(
    rx: Receiver<Messages>,
    duration: u64,
    buckets: u32,
) -> Result<Arc<Mutex<Stats>>, Box<dyn std::error::Error>> {
    let stats = Arc::new(Mutex::new(Stats::new()));
    {
        let mut stats = stats.lock().unwrap();
        stats.timeline = vec![0; buckets.try_into().unwrap()];

    }

    let message = rx.recv().expect("couldnt get sender");
    if message != Messages::ClientStart {
        return Ok(stats);
    }

    let mut root_cert_store = rustls::RootCertStore::empty();

    for cert in
        CertificateDer::pem_file_iter("/home/foxmoss/Projects/fox-xdp/benchmark/certs/root-ca.pem")
            .expect("failed to load certs")
    {
        root_cert_store
            .add(cert.expect("cert failed"))
            .expect("adding cert failed");
    }

    let mut id = 0;
    loop {
        if let Ok(val) = rx.try_recv() {
            if val == Messages::ClientEnd {
                return Ok(stats);
            }
        }

        id += 1;
        let stats = stats.clone();
        let root_store_clone = root_cert_store.clone();
        tokio::task::spawn(async move {
            let _permit = PERMITS.acquire().await.unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store_clone)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
            match TcpStream::connect(&addr).await {
                Err(_) => {}
                Ok(stream) => {
                    let server_name: ServerName = "localhost".try_into().expect("invalid DNS name");
                    let mut tls_stream = connector
                        .connect(server_name, stream)
                        .await
                        .expect("couldnt connect with tls");

                    let content = format!("{}", id);
                    if let Ok(_) = tls_stream.write_all(content.as_bytes()).await {
                        let len = content.len();
                        let mut buf: Vec<u8> = vec![0; len];
                        tls_stream
                            .read_exact(&mut buf)
                            .await
                            .expect("couldnt write");
                        let mut stats = stats.lock().unwrap();

                        if content.as_bytes() != buf {
                            println!("Datat does NOT match");
                            return;
                        }

                        let now = SystemTime::now();
                        let since_start = now
                            .duration_since(stats.started)
                            .expect("time should go forward")
                            .as_millis() as f64;

                        let bucket_size = (duration as f64) * 1000.0;
                        let time_loc = since_start / bucket_size;
                        let mut time_index =
                            (time_loc * (buckets as f64)).round() as usize;

                        if time_index >= stats.timeline.len() {
                            time_index = stats.timeline.len() - 1;
                        }

                        stats.timeline[time_index] += 1;
                        println!("{}", time_index);
                        stats.request_count += 1;
                    }
                }
            }
        });
    }
}
