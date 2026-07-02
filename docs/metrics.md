# Span metrics

With `TracerConfig.EnableMetrics` set, a span processor maintains Prometheus metrics for every span:

| Metric | Type | Description |
|---|---|---|
| `tracing_span_started` | counter | Spans started |
| `tracing_span_ended` | counter | Spans ended |
| `tracing_span_succeeded` | counter | Spans ended with status `Ok` |
| `tracing_span_failed` | counter | Spans ended with status `Error` |
| `tracing_span_current` | gauge | Spans currently in flight |
| `tracing_span_duration` | histogram | Span duration in seconds |

All metrics share the same labels:

- `span_name` — the span name;
- `service` — `service.name` resource attribute;
- `version` — `service.version` resource attribute;
- `env` — `service.namespace` resource attribute;
- `moniker` — `moniker` resource attribute.

Note that `tracing_span_succeeded` / `tracing_span_failed` only count spans whose status was explicitly set — `EndSpan` and `TrackError` do this for you. Spans ended with status `Unset` are counted in `tracing_span_ended` only.

## Serving /metrics

Set `TracerConfig.MetricsPort` and `InitTracer` starts an HTTP server exposing the default Prometheus registry:

```go
cfg.EnableMetrics = true
cfg.MetricsPort = 9090
// GET :9090/metrics
```

The server shuts down when the context passed to `InitTracer` is cancelled. If your service already serves Prometheus metrics, leave `MetricsPort` at zero — the span metrics are registered on the default registry and will appear on your existing endpoint.

## Example queries

Error rate per span over 5 minutes:

```promql
sum by (span_name) (rate(tracing_span_failed[5m]))
/
sum by (span_name) (rate(tracing_span_ended[5m]))
```

p95 span duration:

```promql
histogram_quantile(0.95, sum by (span_name, le) (rate(tracing_span_duration_bucket[5m])))
```
