# ADR-0001 — A span capture to a file, and a tool that reads it

**Status**: Proposed 2026-11-04.

## Context

btc-relayer can record the spans of one command run into a file and read the
file back. Neither part is specific to btc-relayer:

- **The capture.** With `--otel-file PATH` (or `BTCREL_OTEL_FILE`), a command
  adds a span processor beside the exporter that the tracing config selects.
  The processor keeps every span in memory and writes them as one OTLP/JSON
  document when the command ends, or a few seconds after Ctrl-C. A path that
  names a directory gets a new file named after the run. The capture opens one
  root span, so the run is one trace.
- **The readers.** `btc-relayer trace show FILE` ranks span groups by self
  time, grouped by span name and by attributes (`rpc.method` by default), or
  prints the span tree with `--tree`. `btc-relayer trace send FILE` posts the
  spans to an OTLP/HTTP endpoint, so that a trace UI can show a run taken
  before a collector was up.

The readers left btc-relayer on 2026-11-04 (its ADR-0030), because they use
nothing of btc-relayer's own. Their last version is at btc-relayer commit
`28a7eea1`: `cmd/tracecmd.go`, `cmd/traceshow.go`, `cmd/tracesend.go` and
`cmd/otlpjson.go`, with their tests. The capture still lives in btc-relayer's
`cmd/tracefile.go`.

What the code learned, which a new home should keep:

- protojson writes trace and span ids as base64, but OTLP/JSON spells them as
  lowercase hex, and Jaeger and the collector refuse base64. The writer
  converts the ids, and the reader also accepts the base64 that older files
  hold.
- The capture uses the synchronous span processor. The batching one drops
  spans when its queue fills, and those are the slow spans a capture is for.
- A capture can hold tens of thousands of short spans, which stall a trace
  UI. `--min` drops spans shorter than a threshold and attaches each kept span
  to its nearest kept ancestor, so the tree keeps its shape, and the tool
  reports what it dropped.
- Self time, not total time, finds the slow call, because concurrent spans add
  up to more than the run took.

## Decision

1. **This module offers the capture.** An option of `InitTracer`, or a
   function beside it, adds the file sink and the root span, and
   `ShutdownTracer` writes the file. A service keeps only its own flag.
2. **This module ships the reader as a command**, such as `cmd/otlptrace`,
   with `show` and `send` as btc-relayer had them. It reads any OTLP/JSON
   trace file, not only a capture of this module.
3. The id conversion lives in one package that both the sink and the reader
   use.

## Consequences

- btc-relayer and any other service that uses this module get the capture
  without their own copy of it.
- An operator installs the reader once, for every service, with
  `go install github.com/symbiosis-finance/tracing/cmd/otlptrace@latest`.
- Until the reader exists, a capture can be loaded into a trace UI that
  imports OTLP/JSON, or read with jq.
