use crate::auth::BearerToken;
use crate::ingest::{IngestOutcome, RecorderIngest};
use incitape_core::ErrorKind;
use incitape_tape::record::RecordType;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tonic::metadata::MetadataMap;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct GrpcState {
    ingest: Arc<RecorderIngest>,
    auth: Option<BearerToken>,
    max_request_bytes: usize,
}

impl GrpcState {
    pub fn new(
        ingest: Arc<RecorderIngest>,
        auth: Option<BearerToken>,
        max_request_bytes: usize,
    ) -> Self {
        Self {
            ingest,
            auth,
            max_request_bytes,
        }
    }
}

pub async fn serve_grpc(
    addr: SocketAddr,
    state: GrpcState,
    timeout: Duration,
    tls: Option<ServerTlsConfig>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), incitape_core::AppError> {
    let mut builder = Server::builder().timeout(timeout);

    if let Some(tls) = tls {
        builder = builder
            .tls_config(tls)
            .map_err(|e| incitape_core::AppError::internal(format!("grpc tls error: {e}")))?;
    }

    let max_request_bytes = state.max_request_bytes;
    builder
        .add_service(
            TraceServiceServer::new(OtlpGrpcService {
                state: state.clone(),
            })
            .max_decoding_message_size(max_request_bytes)
            .max_encoding_message_size(max_request_bytes),
        )
        .add_service(
            MetricsServiceServer::new(OtlpGrpcService {
                state: state.clone(),
            })
            .max_decoding_message_size(max_request_bytes)
            .max_encoding_message_size(max_request_bytes),
        )
        .add_service(
            LogsServiceServer::new(OtlpGrpcService { state })
                .max_decoding_message_size(max_request_bytes)
                .max_encoding_message_size(max_request_bytes),
        )
        .serve_with_shutdown(addr, shutdown)
        .await
        .map_err(|e| incitape_core::AppError::internal(format!("grpc serve error: {e}")))?;

    Ok(())
}

pub fn tls_config_from_pem(
    cert: &[u8],
    key: &[u8],
) -> Result<ServerTlsConfig, incitape_core::AppError> {
    let identity = Identity::from_pem(cert, key);
    Ok(ServerTlsConfig::new().identity(identity))
}

struct OtlpGrpcService {
    state: GrpcState,
}

#[tonic::async_trait]
impl TraceService for OtlpGrpcService {
    async fn export(
        &self,
        request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        handle_grpc_request(
            &self.state,
            RecordType::Traces,
            request,
            ExportTraceServiceResponse {
                partial_success: None,
            },
        )
        .await
    }
}

#[tonic::async_trait]
impl MetricsService for OtlpGrpcService {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        handle_grpc_request(
            &self.state,
            RecordType::Metrics,
            request,
            ExportMetricsServiceResponse {
                partial_success: None,
            },
        )
        .await
    }
}

#[tonic::async_trait]
impl LogsService for OtlpGrpcService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        handle_grpc_request(
            &self.state,
            RecordType::Logs,
            request,
            ExportLogsServiceResponse {
                partial_success: None,
            },
        )
        .await
    }
}

async fn handle_grpc_request<T: Message, R>(
    state: &GrpcState,
    record_type: RecordType,
    request: Request<T>,
    response: R,
) -> Result<Response<R>, Status> {
    if !authorized(request.metadata(), &state.auth) {
        return Err(Status::unauthenticated("missing or invalid bearer token"));
    }

    let encoded_len = request.get_ref().encoded_len();
    if encoded_len > state.max_request_bytes {
        return Err(Status::resource_exhausted(
            "request exceeds max_record_bytes",
        ));
    }

    let mut buf = Vec::with_capacity(encoded_len);
    request
        .get_ref()
        .encode(&mut buf)
        .map_err(|_| Status::internal("failed to encode request"))?;

    match state.ingest.ingest(record_type, &buf).await {
        IngestOutcome::Accepted => Ok(Response::new(response)),
        IngestOutcome::Rejected(err) => Err(map_rejected(&err)),
        IngestOutcome::Fatal(_) => Err(Status::internal("recorder failure")),
    }
}

fn authorized(metadata: &MetadataMap, auth: &Option<BearerToken>) -> bool {
    match auth {
        None => true,
        Some(token) => metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(|value| token.verify(value))
            .unwrap_or(false),
    }
}

fn map_rejected(err: &incitape_core::AppError) -> Status {
    match err.kind() {
        ErrorKind::Validation => Status::invalid_argument(err.message()),
        ErrorKind::Security => Status::unauthenticated(err.message()),
        _ => Status::internal(err.message()),
    }
}
