# Span logging

With `TracerConfig.EnableLogs` set, a span processor mirrors the span lifecycle to the zap logger passed to `InitTracer`:

| Event | Prefix | Level |
|---|---|---|
| Span start | `⬎ <span name>` | Debug |
| Span event | `⮕ <span name> <event name>` | span level, or per-event override |
| Span end | `⬑ <span name>` | Debug, or Error if the span status is `Error` |

Each line carries the span's attributes as structured zap fields. Depending on `TracerLogsConfig` ([configuration](configuration.md)), lines also include:

- `span.traceID` / `span.ID` (`EnableSpanContextAttrs`, on by default) — lets you jump from a log line straight to the trace;
- `parent.traceID` / `parent.ID` (`EnableParentSpanAttrs`);
- resource attributes (`EnableResourceAttrs`), except `telemetry.*`;
- `span.kind`, `span.duration`, and `span.error` (status description) on end lines.

Event log lines are emitted at span end using the event's original timestamp (via a custom zap clock), so timestamps in logs match the trace timeline.

## Per-event log levels

Span events default to the span's level. Attach `LogLevelAttr` to override per event:

```go
span.AddEvent("cache miss", trace.WithAttributes(
    tracing.LogLevelAttr(zapcore.WarnLevel),
))
```

## Context log fields

`AddLogFields` stores attributes in the context; any span started from that context picks them up automatically:

```go
ctx = tracing.AddLogFields(ctx, tracing.RequestID(reqID))
// every span started with ctx now carries request.id
```

`GetLogFields(ctx)` returns the currently stored attributes.

## Helpers

- `AttributeToZapField(attr)` converts a single OpenTelemetry attribute to a `zap.Field` (invalid attributes become `zap.Skip()`).
- `DefaultZapFields()` returns version / `APP_ENV` / `MONIKER` / `SERVICE` fields — handy for stamping a base logger consistently with the trace resource:

  ```go
  logger := zap.Must(zap.NewProduction()).With(tracing.DefaultZapFields()...)
  ```
