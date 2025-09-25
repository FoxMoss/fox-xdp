use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
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

pub async fn run_client(rx: Receiver<Messages>) -> Result<(), Box<dyn std::error::Error>> {
    let message = rx.recv().expect("couldnt get sender");
    if message != Messages::ClientStart {
        return Ok(());
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

    loop {
        if let Ok(val) = rx.try_recv() {
            if val == Messages::ClientEnd {
                return Ok(());
            }
        }
        let root_store_clone = root_cert_store.clone();
        tokio::task::spawn(async move {
            let _permit = PERMITS.acquire().await.unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store_clone)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
            match TcpStream::connect(&addr).await {
                Err(error) => {}
                Ok(stream) => {
                    let server_name: ServerName = "localhost".try_into().expect("invalid DNS name");
                    let mut tls_stream = connector
                        .connect(server_name, stream)
                        .await
                        .expect("couldnt connect with tls");

                    let content = "hello server";
                    tls_stream
                        .write_all(content.as_bytes())
                        .await
                        .expect("couldnt write");

                    let mut buf: [u8; 3] = [0; 3];
                    tls_stream
                        .read_exact(&mut buf)
                        .await
                        .expect("couldnt write");
                }
            }
        });
    }
}
