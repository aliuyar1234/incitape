import os
import time
import requests
from flask import Flask, request
from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http import Compression as HttpCompression
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HttpSpanExporter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import SpanKind

SERVICE_NAME = os.getenv("SERVICE_NAME", "checkout")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
INSECURE = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
INCITAPE_ENDPOINT = os.getenv("INCITAPE_OTLP_ENDPOINT", "")
INCITAPE_TOKEN = os.getenv("INCITAPE_AUTH_TOKEN", "")
INCITAPE_CA_FILE = os.getenv("INCITAPE_CA_FILE", "")

app = Flask(__name__)

resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
collector_exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=INSECURE)
provider.add_span_processor(SimpleSpanProcessor(collector_exporter))
if INCITAPE_ENDPOINT and INCITAPE_TOKEN and INCITAPE_CA_FILE:
    incitape_headers = {"authorization": f"Bearer {INCITAPE_TOKEN}"}
    incitape_exporter = HttpSpanExporter(
        endpoint=INCITAPE_ENDPOINT,
        certificate_file=INCITAPE_CA_FILE,
        headers=incitape_headers,
        compression=HttpCompression.NoCompression,
    )
    provider.add_span_processor(SimpleSpanProcessor(incitape_exporter))
trace.set_tracer_provider(provider)

tracer = trace.get_tracer(__name__)

@app.route("/checkout")
def checkout():
    ctx = propagate.extract(request.headers)
    with tracer.start_as_current_span("checkout.request", context=ctx, kind=SpanKind.SERVER):
        time.sleep(0.02)
        with tracer.start_as_current_span("payments.call", kind=SpanKind.CLIENT):
            headers = {}
            propagate.inject(headers)
            resp = requests.get("http://payments:8080/pay", headers=headers, timeout=2)
        return f"checkout -> {resp.text}\n"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
