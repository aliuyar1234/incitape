use incitape_core::{AppError, AppResult};
use incitape_tape::record::RecordType;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::transport::Endpoint;

pub struct GrpcExporter {
    trace_client: TraceServiceClient<Channel>,
    metrics_client: MetricsServiceClient<Channel>,
    logs_client: LogsServiceClient<Channel>,
}

impl GrpcExporter {
    pub async fn connect(
        endpoint: &str,
        connect_timeout: Duration,
        rpc_timeout: Duration,
    ) -> AppResult<Self> {
        let endpoint = Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| AppError::usage(format!("invalid --to endpoint: {e}")))?
            .connect_timeout(connect_timeout)
            .timeout(rpc_timeout);
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| AppError::internal(format!("failed to connect: {e}")))?;
        Ok(Self {
            trace_client: TraceServiceClient::new(channel.clone()),
            metrics_client: MetricsServiceClient::new(channel.clone()),
            logs_client: LogsServiceClient::new(channel),
        })
    }

    pub async fn send(&mut self, record_type: RecordType, payload: &[u8]) -> AppResult<()> {
        match record_type {
            RecordType::Traces => {
                let request = ExportTraceServiceRequest::decode(payload)
                    .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;
                self.trace_client
                    .export(request)
                    .await
                    .map_err(|e| AppError::internal(format!("trace export failed: {e}")))?;
            }
            RecordType::Metrics => {
                let request = ExportMetricsServiceRequest::decode(payload)
                    .map_err(|e| AppError::validation(format!("metrics decode error: {e}")))?;
                self.metrics_client
                    .export(request)
                    .await
                    .map_err(|e| AppError::internal(format!("metrics export failed: {e}")))?;
            }
            RecordType::Logs => {
                let request = ExportLogsServiceRequest::decode(payload)
                    .map_err(|e| AppError::validation(format!("logs decode error: {e}")))?;
                self.logs_client
                    .export(request)
                    .await
                    .map_err(|e| AppError::internal(format!("logs export failed: {e}")))?;
            }
        }
        Ok(())
    }
}
