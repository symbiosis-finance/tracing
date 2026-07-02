# Getting started

## Installation

```sh
go get github.com/symbiosis-finance/tracing
```

Requires Go 1.26+.

## Initialization

Call `InitTracer` once at startup. It builds the exporter, registers a global OpenTelemetry tracer provider, and installs a composite W3C propagator (`traceparent` + `baggage`):

```go
ctx := context.Background()
logger := zap.Must(zap.NewProduction())

cfg := tracing.DefaultTracerConfig()
cfg.GrpcUrl = "http://tempo:4317"

tracing.InitTracer(ctx, cfg, logger)
defer tracing.ShutdownTracer()
```

`ShutdownTracer` flushes pending spans with a 1-second timeout; call it on the way out (a `defer` in `main` works well).

Extra resource attributes can be passed as trailing arguments — they take precedence over the auto-detected ones:

```go
tracing.InitTracer(ctx, cfg, logger,
    semconv.ServiceName("my-service"),
    tracing.Moniker("validator-1"),
)
```

See [Configuration](configuration.md) for the full `TracerConfig` reference and the list of automatically populated resource attributes.

## Creating spans

`StartSpan` / `EndSpan` are thin wrappers around the OpenTelemetry API designed for the named-return + `defer` pattern:

```go
func processBlock(ctx context.Context, num uint64) (err error) {
    ctx, span := tracing.StartSpan(ctx, "processBlock",
        trace.WithAttributes(tracing.BlockNumber(num)))
    defer tracing.EndSpan(span, &err)

    // ... use ctx for downstream calls so they become child spans ...
    return nil
}
```

- `StartSpan` uses the package-level tracer and, when the context has a deadline, records the remaining time as a `context_timeout` attribute.
- `EndSpan` dereferences the error pointer at return time: a non-nil error is recorded on the span and sets status `Error`; a nil error sets status `Ok`. Extra attributes passed to `EndSpan` are set just before the span ends.

To record an error without ending the span, use `TrackError(span, err)`.

## What you get

With `EnableLogs` and `EnableMetrics` turned on, every span automatically:

- appears in your tracing backend (Tempo, Jaeger, ...) via OTLP;
- is logged to zap at start and end with trace/span IDs, duration, and attributes ([details](logging.md));
- updates Prometheus counters and a duration histogram labeled by span name ([details](metrics.md)).
