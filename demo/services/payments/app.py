import os
import time
from flask import Flask
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.flask import FlaskInstrumentor

SERVICE_NAME = os.getenv("SERVICE_NAME", "payments")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
INSECURE = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"

app = Flask(__name__)

resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=INSECURE)
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)

FlaskInstrumentor().instrument_app(app)

@app.route("/pay")
def pay():
    time.sleep(0.01)
    return "payments ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
