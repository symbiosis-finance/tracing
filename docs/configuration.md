# Configuration

## TracerConfig

```go
type TracerConfig struct {
    // Only one of outputs is used
    EnableStdout bool
    GrpcUrl      string
    HttpUrl      string

    EnableLogs    bool // Enable logging of span's start/end
    LogFilters    TracerLogsConfig
    EnableMetrics bool     // Enable span metrics
    MetricsPort   int      // Port to expose metrics on
    SpanBlacklist []string // List of spans to filter out
}
```

`DefaultTracerConfig()` returns a config with `LogFilters.EnableSpanContextAttrs = true` and everything else off.

`TracerConfig` also implements `GetTracingConfig()`, so it can be embedded in a larger service config struct and passed around behind an interface.

### Exporter selection

Exactly one exporter is chosen, checked in this order:

1. `EnableStdout` — pretty-printed spans to stdout (`stdouttrace`), useful for local development.
2. `GrpcUrl` — OTLP over gRPC (`otlptracegrpc.WithEndpointURL`).
3. `HttpUrl` — OTLP over HTTP (`otlptracehttp.WithEndpointURL`). If the URL contains userinfo (`https://user:pass@collector/...`), it is sent as a basic-auth `Authorization` header.

If none is set, no exporter is registered — spans are still processed by the logging/metrics span processors, which is a valid setup for services that only want span logs and metrics.

Spans are exported through a batching span processor (`sdktrace.WithBatcher`).

### Logging and metrics

- `EnableLogs` attaches the [logging span processor](logging.md); `LogFilters` controls which extra fields are included in each log line:

  ```go
  type TracerLogsConfig struct {
      EnableResourceAttrs    bool // resource attributes on every line
      EnableParentSpanAttrs  bool // parent trace/span IDs
      EnableSpanContextAttrs bool // own trace/span IDs (on by default)
  }
  ```

- `EnableMetrics` attaches the [metrics span processor](metrics.md).
- `MetricsPort`, when non-zero, starts an HTTP server on `:<port>` serving Prometheus metrics at `/metrics`. It shuts down when the context passed to `InitTracer` is cancelled.

### SpanBlacklist

Span names listed here are dropped by a custom sampler (`Decision: Drop`) — they are not exported, logged, or counted. Use it to silence high-frequency noise (health checks, polling loops). All other spans are always sampled (`RecordAndSample`).

## Resource attributes

`InitTracer` builds the OpenTelemetry resource from the attributes you pass, filling in any that are absent:

| Attribute | Source |
|---|---|
| `host.name` | Reverse-DNS lookup of the host's IP (1s timeout), falling back to `os.Hostname()` |
| `service.instance.id` | Random UUID per process |
| `service.name` | `SERVICE` environment variable |
| `service.namespace` | `APP_ENV` environment variable |
| `service.version` | `Version` package variable (see below) |
| `moniker` | `MONIKER` environment variable |
| `process.command` | `os.Args[0]` |
| `telemetry.sdk.*` | OpenTelemetry SDK name/language/version |

Explicitly passed attributes always win; environment-derived ones are only used when the variable is set.

### Version stamping

`tracing.Version` defaults to `"notset"` and is meant to be injected at build time:

```sh
go build -ldflags "-X=github.com/symbiosis-finance/tracing.Version=v1.2.3" ./...
```

It becomes the `service.version` resource attribute and the `version` label on span metrics.
