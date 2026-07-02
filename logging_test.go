package tracing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAttributeToZapField(t *testing.T) {
	for name, tc := range map[string]struct {
		attr attribute.KeyValue
		want any
	}{
		"bool":         {attribute.Bool("k", true), true},
		"int64":        {attribute.Int64("k", 42), int64(42)},
		"float64":      {attribute.Float64("k", 4.2), 4.2},
		"string":       {attribute.String("k", "v"), "v"},
		// the map encoder stores array elements as []interface{}
		"bool-slice":   {attribute.BoolSlice("k", []bool{true, false}), []any{true, false}},
		"int64-slice":  {attribute.Int64Slice("k", []int64{1, 2}), []any{int64(1), int64(2)}},
		"float-slice":  {attribute.Float64Slice("k", []float64{1.5}), []any{1.5}},
		"string-slice": {attribute.StringSlice("k", []string{"a", "b"}), []any{"a", "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			AttributeToZapField(tc.attr).AddTo(enc)
			assert.Equal(t, tc.want, enc.Fields["k"])
		})
	}

	assert.Equal(t, zapcore.SkipType, AttributeToZapField(attribute.KeyValue{}).Type, "invalid attribute should be skipped")
}

func TestAddGetLogFields(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, GetLogFields(ctx))

	ctx = AddLogFields(ctx, attribute.String("a", "1"))
	ctx = AddLogFields(ctx, attribute.String("b", "2"))
	fields := GetLogFields(ctx)
	require.Len(t, fields, 2)
	assert.Equal(t, attribute.String("a", "1"), fields[0])
	assert.Equal(t, attribute.String("b", "2"), fields[1])
}

func TestLogLevelAttr(t *testing.T) {
	ev := sdktrace.Event{Attributes: []attribute.KeyValue{LogLevelAttr(zapcore.WarnLevel)}}
	level, found := getLogLevel(ev)
	require.True(t, found)
	assert.Equal(t, zapcore.WarnLevel, level)

	_, found = getLogLevel(sdktrace.Event{})
	assert.False(t, found)
}

func newObservedLoggingProvider(t *testing.T, cfg TracerLogsConfig, res *resource.Resource) (trace.Tracer, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSpanProcessor(newLoggingSpanProcessor(zap.New(core), cfg)),
	}
	if res != nil {
		opts = append(opts, sdktrace.WithResource(res))
	}
	tp := sdktrace.NewTracerProvider(opts...)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp.Tracer("test"), logs
}

func TestLoggingSpanProcessor(t *testing.T) {
	tracer, logs := newObservedLoggingProvider(t, DefaultTracerConfig().LogFilters, nil)

	ctx := AddLogFields(context.Background(), attribute.String("request.id", "req-1"))
	ctx, parent := tracer.Start(ctx, "parent")
	_, span := tracer.Start(ctx, "op")
	span.AddEvent("cache-miss", trace.WithAttributes(LogLevelAttr(zapcore.WarnLevel)))
	span.AddEvent("plain-event")
	span.SetStatus(codes.Error, "boom")
	span.End()
	parent.End()

	entries := logs.All()
	require.Len(t, entries, 6) // 2 starts + 2 events + 2 ends

	byMessage := make(map[string]observer.LoggedEntry, len(entries))
	for _, e := range entries {
		byMessage[e.Message] = e
	}

	start, ok := byMessage["⬎ op"]
	require.True(t, ok, "expected span start log")
	assert.Equal(t, zapcore.DebugLevel, start.Level)
	assert.Equal(t, "req-1", start.ContextMap()["request.id"], "context log fields should be attached to the span")
	assert.Contains(t, start.ContextMap(), "span.traceID")
	assert.Contains(t, start.ContextMap(), "span.ID")

	warnEvent, ok := byMessage["⮕ op cache-miss"]
	require.True(t, ok, "expected span event log")
	assert.Equal(t, zapcore.WarnLevel, warnEvent.Level, "log-level attr should override event level")

	plainEvent, ok := byMessage["⮕ op plain-event"]
	require.True(t, ok)
	assert.Equal(t, zapcore.ErrorLevel, plainEvent.Level, "event level should default to span level")

	end, ok := byMessage["⬑ op"]
	require.True(t, ok, "expected span end log")
	assert.Equal(t, zapcore.ErrorLevel, end.Level, "failed span should be logged at error level")
	assert.Equal(t, "boom", end.ContextMap()["span.error"])
	assert.Contains(t, end.ContextMap(), "span.duration")

	parentEnd, ok := byMessage["⬑ parent"]
	require.True(t, ok)
	assert.Equal(t, zapcore.DebugLevel, parentEnd.Level, "span without error status should be logged at debug level")
}

func TestLoggingSpanProcessorFilters(t *testing.T) {
	res := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("svc-log"),
		attribute.String("telemetry.sdk.name", "opentelemetry"),
	)
	cfg := TracerLogsConfig{
		EnableResourceAttrs:    true,
		EnableParentSpanAttrs:  true,
		EnableSpanContextAttrs: false,
	}
	tracer, logs := newObservedLoggingProvider(t, cfg, res)

	ctx, parent := tracer.Start(context.Background(), "parent")
	_, span := tracer.Start(ctx, "child")
	span.End()
	parent.End()

	var end observer.LoggedEntry
	found := false
	for _, e := range logs.All() {
		if e.Message == "⬑ child" {
			end, found = e, true
		}
	}
	require.True(t, found, "expected child span end log")

	fields := end.ContextMap()
	assert.Equal(t, "svc-log", fields["service.name"], "resource attrs should be logged")
	assert.NotContains(t, fields, "telemetry.sdk.name", "telemetry.* resource attrs should be filtered out")
	assert.Contains(t, fields, "parent.ID", "parent span attrs should be logged")
	assert.NotContains(t, fields, "span.ID", "span context attrs should be disabled")
}

func TestSpanDurationField(t *testing.T) {
	tracer, logs := newObservedLoggingProvider(t, DefaultTracerConfig().LogFilters, nil)

	_, span := tracer.Start(context.Background(), "timed")
	time.Sleep(time.Millisecond)
	span.End()

	entries := logs.FilterMessage("⬑ timed").All()
	require.Len(t, entries, 1)
	duration, ok := entries[0].ContextMap()["span.duration"].(time.Duration)
	require.True(t, ok, "span.duration should be a duration field")
	assert.Positive(t, duration)
}

func TestDefaultZapFields(t *testing.T) {
	t.Setenv("SERVICE", "svc-fields")
	t.Setenv("APP_ENV", "env-fields")
	t.Setenv("MONIKER", "moniker-fields")

	enc := zapcore.NewMapObjectEncoder()
	for _, f := range DefaultZapFields() {
		f.AddTo(enc)
	}

	assert.Equal(t, "svc-fields", enc.Fields["service.name"])
	assert.Equal(t, "env-fields", enc.Fields["service.namespace"])
	assert.Equal(t, "moniker-fields", enc.Fields["moniker"])
	assert.Equal(t, VersionNotSet, enc.Fields["service.version"])
}
