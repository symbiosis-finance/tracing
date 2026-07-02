# tracing

[![Go Reference](https://pkg.go.dev/badge/github.com/symbiosis-finance/tracing.svg)](https://pkg.go.dev/github.com/symbiosis-finance/tracing)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Opinionated OpenTelemetry tracing toolkit for Go services. One `InitTracer` call wires up OTLP export, structured span logging via [zap](https://github.com/uber-go/zap), Prometheus span metrics, and rich resource attributes — so every service emits consistent telemetry with near-zero boilerplate.

## Features

- **One-call setup** — `InitTracer` configures the exporter (OTLP gRPC / OTLP HTTP / stdout), global tracer provider, and W3C `traceparent` + `baggage` propagation.
- **Span logging** — every span start/end and span event is mirrored to zap, with trace/span IDs, duration, and attributes as structured fields.
- **Span metrics** — Prometheus counters, gauge, and duration histogram per span name, served on a built-in `/metrics` endpoint.
- **Ergonomic span helpers** — `StartSpan` / `EndSpan` pair designed for `defer`, with automatic error recording and status codes.
- **Automatic resource attributes** — hostname (reverse-DNS resolved), service instance ID, version (via `-ldflags`), and `SERVICE` / `APP_ENV` / `MONIKER` environment variables.
- **Web3 semantic conventions** — typed attribute constructors for chain ID, block number/hash, transaction ID, and log index.
- **Request ID propagation** — `baggage` subpackage carries `request.id` across service boundaries.
- **Span blacklist** — drop noisy spans by name at the sampler level.

## Installation

```sh
go get github.com/symbiosis-finance/tracing
```

## Quick start

```go
package main

import (
	"context"

	"github.com/symbiosis-finance/tracing"
	"go.uber.org/zap"
)

func main() {
	ctx := context.Background()
	logger := zap.Must(zap.NewProduction())

	cfg := tracing.DefaultTracerConfig()
	cfg.GrpcUrl = "http://tempo:4317" // OTLP gRPC endpoint
	cfg.EnableLogs = true             // mirror spans to zap
	cfg.EnableMetrics = true          // Prometheus span metrics
	cfg.MetricsPort = 9090            // serve /metrics

	tracing.InitTracer(ctx, cfg, logger)
	defer tracing.ShutdownTracer()

	if err := doWork(ctx); err != nil {
		logger.Error("work failed", zap.Error(err))
	}
}

func doWork(ctx context.Context) (err error) {
	ctx, span := tracing.StartSpan(ctx, "doWork")
	defer tracing.EndSpan(span, &err) // records err and sets span status

	// ... your logic ...
	return nil
}
```

## Documentation

- [Getting started](docs/getting-started.md) — setup, span lifecycle, error tracking
- [Configuration](docs/configuration.md) — `TracerConfig` reference, exporters, resource attributes
- [Span logging](docs/logging.md) — zap integration, per-event log levels, context log fields
- [Span metrics](docs/metrics.md) — exposed Prometheus metrics and labels
- [Attributes](docs/attributes.md) — Web3 semantic conventions, attribute helpers
- [Propagation](docs/propagation.md) — cross-service context, request IDs, manual store/load

## License

[MIT](LICENSE)
