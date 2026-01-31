use crate::auth::BearerToken;
use crate::ingest::{IngestOutcome, RecorderIngest};
use bytes::{Bytes, BytesMut};
use hyper::body::HttpBody;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use incitape_core::{AppError, ErrorKind};
use incitape_tape::record::RecordType;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct HttpState {
    ingest: Arc<RecorderIngest>,
    auth: Option<BearerToken>,
    max_request_bytes: usize,
    timeout: Duration,
}

impl HttpState {
    pub fn new(
        ingest: Arc<RecorderIngest>,
        auth: Option<BearerToken>,
        max_request_bytes: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            ingest,
            auth,
            max_request_bytes,
            timeout,
        }
    }
}

pub async fn serve_http(
    addr: SocketAddr,
    mut state: HttpState,
    timeout: Duration,
    tls: Option<crate::tls::RustlsServerConfig>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), AppError> {
    state.timeout = timeout;
    if let Some(tls) = tls {
        serve_https(addr, state, tls, shutdown).await
    } else {
        serve_plain_http(addr, state, shutdown).await
    }
}

async fn serve_plain_http(
    addr: SocketAddr,
    state: HttpState,
    shutdown: watch::Receiver<bool>,
) -> Result<(), AppError> {
    let make_svc = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_request(state, req).await) }
            }))
        }
    });

    hyper::Server::bind(&addr)
        .serve(make_svc)
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
        .map_err(|e| AppError::internal(format!("http server error: {e}")))?;
    Ok(())
}

async fn serve_https(
    addr: SocketAddr,
    state: HttpState,
    tls: crate::tls::RustlsServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AppError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::internal(format!("http bind error: {e}")))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            incoming = listener.accept() => {
                let (stream, _) = incoming.map_err(|e| AppError::internal(format!("http accept error: {e}")))?;
                let acceptor = acceptor.clone();
                let state = state.clone();
                let mut shutdown_rx = shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    let service = service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(handle_request(state, req).await) }
                    });
                    if *shutdown_rx.borrow() {
                        return;
                    }
                    tokio::select! {
                        _ = shutdown_rx.changed() => {}
                        _ = hyper::server::conn::Http::new().serve_connection(tls_stream, service) => {}
                    }
                }));
            }
        }
    }

    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn handle_request(state: HttpState, req: Request<Body>) -> Response<Body> {
    match tokio::time::timeout(state.timeout, handle_request_inner(state, req)).await {
        Ok(resp) => resp,
        Err(_) => response(StatusCode::REQUEST_TIMEOUT),
    }
}

async fn handle_request_inner(state: HttpState, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }

    let record_type = match req.uri().path() {
        "/v1/traces" => RecordType::Traces,
        "/v1/metrics" => RecordType::Metrics,
        "/v1/logs" => RecordType::Logs,
        _ => return response(StatusCode::NOT_FOUND),
    };

    if !authorized(req.headers(), &state.auth) {
        return response(StatusCode::UNAUTHORIZED);
    }

    if !content_type_ok(req.headers()) {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    let body = match read_body_limited(req.into_body(), state.max_request_bytes).await {
        Ok(body) => body,
        Err(status) => return response(status),
    };

    match state.ingest.ingest(record_type, &body).await {
        IngestOutcome::Accepted => response(StatusCode::OK),
        IngestOutcome::Rejected(err) => response(map_rejected(&err)),
        IngestOutcome::Fatal(_) => response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn read_body_limited(body: Body, max: usize) -> Result<Bytes, StatusCode> {
    let mut body = body;
    let mut buf = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if buf.len() + chunk.len() > max {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

fn authorized(headers: &hyper::HeaderMap, auth: &Option<BearerToken>) -> bool {
    match auth {
        None => true,
        Some(token) => headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| token.verify(value))
            .unwrap_or(false),
    }
}

fn content_type_ok(headers: &hyper::HeaderMap) -> bool {
    match headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        None => true,
        Some(value) => {
            let value = value.to_ascii_lowercase();
            value.starts_with("application/x-protobuf")
                || value.starts_with("application/octet-stream")
        }
    }
}

fn map_rejected(err: &AppError) -> StatusCode {
    match err.kind() {
        ErrorKind::Validation => {
            if err.message().contains("max_record_bytes") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            }
        }
        ErrorKind::Security => StatusCode::UNAUTHORIZED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
