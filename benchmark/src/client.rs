use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncReadExt, AsyncWriteExt, copy, split, stdin as tokio_stdin, stdout as tokio_stdout,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

use crate::server::Messages;

static PERMITS: Semaphore = Semaphore::const_new(500);

#[derive(Clone)]
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

pub async fn run_client(
    rx: Receiver<Messages>,
) -> Result<Arc<Mutex<Stats>>, Box<dyn std::error::Error>> {
    let stats = Arc::new(Mutex::new(Stats::new()));

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
                            .expect("time should go forward");

                        stats.timeline.push(since_start);
                        stats.request_count += 1;
                    }
                }
            }
        });
    }
}
