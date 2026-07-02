package tracing

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

func findAttr(attrs []attribute.KeyValue, key attribute.Key) (attribute.Value, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func setupGlobalTracer(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return rec
}

func setupGlobalPropagator(t *testing.T) {
	t.Helper()
	prev := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
}

func TestStartSpanAddsContextTimeout(t *testing.T) {
	rec := setupGlobalTracer(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, span := StartSpan(ctx, "with-deadline")
	span.End()

	_, span = StartSpan(context.Background(), "without-deadline")
	span.End()

	ended := rec.Ended()
	require.Len(t, ended, 2)
	_, found := findAttr(ended[0].Attributes(), "context_timeout")
	assert.True(t, found, "span with deadline should have context_timeout attribute")
	_, found = findAttr(ended[1].Attributes(), "context_timeout")
	assert.False(t, found, "span without deadline should not have context_timeout attribute")
}

func TestEndSpan(t *testing.T) {
	rec := setupGlobalTracer(t)

	_, span := StartSpan(context.Background(), "failing")
	err := errors.New("boom")
	EndSpan(span, &err, attribute.String("extra", "value"))

	_, span = StartSpan(context.Background(), "succeeding")
	var nilErr error
	EndSpan(span, &nilErr)

	ended := rec.Ended()
	require.Len(t, ended, 2)

	failing := ended[0]
	assert.Equal(t, codes.Error, failing.Status().Code)
	assert.Equal(t, "boom", failing.Status().Description)
	extra, found := findAttr(failing.Attributes(), "extra")
	require.True(t, found)
	assert.Equal(t, "value", extra.AsString())

	assert.Equal(t, codes.Ok, ended[1].Status().Code)
}

func TestTrackError(t *testing.T) {
	rec := setupGlobalTracer(t)

	_, span := StartSpan(context.Background(), "op")
	TrackError(span, errors.New("kaboom"))
	span.End()

	ended := rec.Ended()
	require.Len(t, ended, 1)
	assert.Equal(t, codes.Error, ended[0].Status().Code)
	assert.NotEmpty(t, ended[0].Events(), "expected recorded exception event")
}

func TestFilteringSampler(t *testing.T) {
	fs := filteringSampler{blacklistedSpans: map[string]any{"noisy": nil}}

	res := fs.ShouldSample(sdktrace.SamplingParameters{ParentContext: context.Background(), Name: "noisy"})
	assert.Equal(t, sdktrace.Drop, res.Decision)

	res = fs.ShouldSample(sdktrace.SamplingParameters{ParentContext: context.Background(), Name: "useful"})
	assert.Equal(t, sdktrace.RecordAndSample, res.Decision)

	assert.NotEmpty(t, fs.Description())
}

func TestSpanBlacklistDropsSpans(t *testing.T) {
	cfg := DefaultTracerConfig()
	cfg.SpanBlacklist = []string{"noisy"}
	tp := newTraceProvider(context.Background(), nil, cfg, zap.NewNop(), []attribute.KeyValue{semconv.HostName("test-host")})
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	rec := tracetest.NewSpanRecorder()
	tp.RegisterSpanProcessor(rec)

	tracer := tp.Tracer("test")
	_, span := tracer.Start(context.Background(), "noisy")
	span.End()
	_, span = tracer.Start(context.Background(), "useful")
	span.End()

	ended := rec.Ended()
	require.Len(t, ended, 1, "blacklisted span should be dropped")
	assert.Equal(t, "useful", ended[0].Name())
}

func TestNewTraceProviderResource(t *testing.T) {
	t.Setenv("SERVICE", "svc-from-env")
	t.Setenv("APP_ENV", "env-from-env")
	t.Setenv("MONIKER", "moniker-from-env")

	cfg := DefaultTracerConfig()
	cfg.EnableLogs = true
	cfg.EnableMetrics = true
	tp := newTraceProvider(context.Background(), nil, cfg, zap.NewNop(), []attribute.KeyValue{
		semconv.HostName("custom-host"),
	})
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	rec := tracetest.NewSpanRecorder()
	tp.RegisterSpanProcessor(rec)

	_, span := tp.Tracer("test").Start(context.Background(), "resource-probe")
	span.End()

	ended := rec.Ended()
	require.Len(t, ended, 1)
	res := ended[0].Resource().Attributes()
	for key, want := range map[attribute.Key]string{
		semconv.HostNameKey:         "custom-host", // explicit attr wins over lookup
		semconv.ServiceNameKey:      "svc-from-env",
		semconv.ServiceNamespaceKey: "env-from-env",
		MonikerKey:                  "moniker-from-env",
		semconv.ServiceVersionKey:   VersionNotSet,
	} {
		v, found := findAttr(res, key)
		require.True(t, found, "resource attr %s missing", key)
		assert.Equal(t, want, v.AsString(), "resource attr %s", key)
	}
	_, found := findAttr(res, semconv.ServiceInstanceIDKey)
	assert.True(t, found, "expected service.instance.id resource attribute")
}

func TestAddAttrIfAbsent(t *testing.T) {
	attrs := make(attrMap)

	addAttrIfAbsent(attrs, semconv.HostName("first"))
	addAttrIfAbsent(attrs, semconv.HostName("second"))
	assert.Equal(t, "first", attrs[semconv.HostNameKey].Value.AsString(), "existing attr should be kept")

	addAttrIfAbsent(attrs, attribute.KeyValue{})
	assert.Len(t, attrs, 1, "invalid attr should not be added")
}

func TestStoreLoadTrace(t *testing.T) {
	setupGlobalTracer(t)
	setupGlobalPropagator(t)

	ctx, span := StartSpan(context.Background(), "source")
	defer span.End()

	carrier := StoreTrace(ctx)
	require.NotEmpty(t, carrier)

	loaded := LoadTrace(context.Background(), carrier)
	got := trace.SpanContextFromContext(loaded)
	want := span.SpanContext()
	assert.Equal(t, want.TraceID(), got.TraceID())
	assert.Equal(t, want.SpanID(), got.SpanID())
}

type nilStringerProbe struct{}

func (*nilStringerProbe) String() string { return "probe" }

func TestNilStringer(t *testing.T) {
	assert.Equal(t, "<nil>", NilStringer("k", nil).Value.AsString())

	var nilPtr *nilStringerProbe
	assert.Equal(t, "<nil>", NilStringer("k", nilPtr).Value.AsString())

	assert.Equal(t, "1s", NilStringer("k", time.Second).Value.AsString())
}

func TestErrorAttr(t *testing.T) {
	assert.False(t, ErrorAttr("err", nil).Valid(), "nil error should produce invalid attribute")
	assert.Equal(t, "oops", ErrorAttr("err", errors.New("oops")).Value.AsString())
}

func TestStringerSlice(t *testing.T) {
	attr := StringerSlice("durations", []time.Duration{time.Second, time.Minute})
	assert.Equal(t, []string{"1s", "1m0s"}, attr.Value.AsStringSlice())
}

func TestMap(t *testing.T) {
	doubled := slices.Collect(Map(slices.Values([]int{1, 2, 3}), func(i int) int { return i * 2 }))
	assert.Equal(t, []int{2, 4, 6}, doubled)

	for range Map(slices.Values([]int{1, 2, 3}), func(i int) int { return i }) {
		break // cover early termination
	}
}

func TestMap2(t *testing.T) {
	got := maps.Collect(Map2(slices.Values([]string{"a", "bb"}), func(s string) (string, int) { return s, len(s) }))
	assert.Equal(t, map[string]int{"a": 1, "bb": 2}, got)

	for range Map2(slices.Values([]string{"a", "b"}), func(s string) (string, string) { return s, s }) {
		break // cover early termination
	}
}

func TestBasicAuthOption(t *testing.T) {
	assert.Nil(t, basicAuthOption("http://collector:4318/v1/traces"))
	assert.NotNil(t, basicAuthOption("http://user:pass@collector:4318/v1/traces"))
}

func TestInitTracerAndShutdown(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	for name, cfg := range map[string]TracerConfig{
		"no-exporter": DefaultTracerConfig(),
		"stdout":      {EnableStdout: true},
		"grpc":        {GrpcUrl: "http://localhost:4317"},
		"http-auth":   {HttpUrl: "http://user:pass@localhost:4318"},
	} {
		t.Run(name, func(t *testing.T) {
			InitTracer(context.Background(), cfg, zap.NewNop(), semconv.HostName("test-host"))
			_, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider)
			require.True(t, ok, "expected sdk tracer provider to be registered globally")

			// only create a span when nothing would try to export it
			if !cfg.EnableStdout && cfg.GrpcUrl == "" && cfg.HttpUrl == "" {
				_, span := StartSpan(context.Background(), "smoke")
				assert.True(t, span.SpanContext().IsValid())
				span.End()
			}
			ShutdownTracer()
		})
	}
}
