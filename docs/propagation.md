# Context propagation

`InitTracer` installs a composite propagator with W3C [Trace Context](https://www.w3.org/TR/trace-context/) (`traceparent`/`tracestate`) and [Baggage](https://www.w3.org/TR/baggage/) headers, so any instrumentation that uses the global `otel.GetTextMapPropagator()` (otelhttp, otelgrpc, ...) propagates both automatically.

## Request IDs via baggage

The `baggage` subpackage carries a `request.id` value across service boundaries:

```go
import "github.com/symbiosis-finance/tracing/baggage"

// at the edge (HTTP handler, queue consumer, ...)
ctx = baggage.WithRequestID(ctx, requestID)

// anywhere downstream, including other services
id := baggage.RequestIDFromContext(ctx)
```

Because it rides in the standard `baggage` header, the request ID survives process hops as long as both sides use the OpenTelemetry propagator.

`WithRequestID` builds a fresh baggage containing just the `request.id` member, so set it once at the request edge before adding anything else to the baggage.

To also stamp the request ID on spans and log lines, combine it with `AddLogFields`:

```go
ctx = tracing.AddLogFields(ctx, tracing.RequestID(id))
```

## Manual store / load

For transports without header support (message queues, database-persisted jobs, cron handoffs), serialize the trace context yourself:

```go
// producer
carrier := tracing.StoreTrace(ctx) // propagation.MapCarrier, a map[string]string
payload.Trace = carrier            // e.g. marshal to JSON alongside the job

// consumer
ctx = tracing.LoadTrace(ctx, payload.Trace)
ctx, span := tracing.StartSpan(ctx, "consumeJob") // child of the producer's span
```

`StoreTrace` injects the current context into a `MapCarrier` using the global propagator; `LoadTrace` extracts it back. Both trace context and baggage (including the request ID) round-trip through the carrier.
