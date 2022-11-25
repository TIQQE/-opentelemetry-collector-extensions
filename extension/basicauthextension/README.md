# Basic Authenticator with private/public solution

## Configuration

```yaml
extensions:
  health_check:
  basicauth/server:
    htpasswd:
      inline: |
        NONE:NONE
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: basicauth/server

processors:
  groupbytrace:
  batch/traces:
    timeout: 10s
  batch/metrics:
    timeout: 10s

exporters:
  awsxray:
    region: eu-north-1
    index_all_attributes: true
  awsemf:

service:
  extensions: [health_check, basicauth/server]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [groupbytrace,batch/traces]
      exporters: [awsxray]
    metrics:
      receivers: [otlp]
      processors: [batch/metrics]
      exporters: [awsemf]

```

[beta]:https://github.com/open-telemetry/opentelemetry-collector#beta
[contrib]:https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib