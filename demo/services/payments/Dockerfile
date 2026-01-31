FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317
ENV OTEL_EXPORTER_OTLP_INSECURE=true
ENV SERVICE_NAME=service
EXPOSE 8080
CMD ["python", "app.py"]
