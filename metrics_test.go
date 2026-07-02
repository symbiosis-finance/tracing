package tracing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.uber.org/zap"
)

func TestMetricsSpanProcessor(t *testing.T) {
	res := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("svc-metrics"),
		semconv.ServiceVersion("v-test"),
		semconv.ServiceNamespace("env-test"),
		Moniker("moniker-test"),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(newMetricsSpanProcessor()),
		sdktrace.WithResource(res),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	tracer := tp.Tracer("test")

	// span_name is part of the label set, so a unique name isolates this test
	// from any other spans touching the global metric vectors
	labels := prometheus.Labels{
		"span_name": "metrics-probe",
		"service":   "svc-metrics",
		"version":   "v-test",
		"env":       "env-test",
		"moniker":   "moniker-test",
	}

	_, okSpan := tracer.Start(context.Background(), "metrics-probe")
	assert.Equal(t, 1.0, testutil.ToFloat64(spanStarted.With(labels)))
	assert.Equal(t, 1.0, testutil.ToFloat64(spanCurrent.With(labels)))

	okSpan.SetStatus(codes.Ok, "")
	okSpan.End()
	assert.Equal(t, 1.0, testutil.ToFloat64(spanEnded.With(labels)))
	assert.Equal(t, 1.0, testutil.ToFloat64(spanSucceeded.With(labels)))
	assert.Equal(t, 0.0, testutil.ToFloat64(spanCurrent.With(labels)))
	assert.Equal(t, 0.0, testutil.ToFloat64(spanFailed.With(labels)))

	_, failSpan := tracer.Start(context.Background(), "metrics-probe")
	failSpan.SetStatus(codes.Error, "boom")
	failSpan.End()
	assert.Equal(t, 2.0, testutil.ToFloat64(spanEnded.With(labels)))
	assert.Equal(t, 1.0, testutil.ToFloat64(spanFailed.With(labels)))
	assert.Equal(t, 1.0, testutil.ToFloat64(spanSucceeded.With(labels)))
}

func TestGetSpanLabels(t *testing.T) {
	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName("svc-only"))
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	rec := newSpanCapture()
	tp.RegisterSpanProcessor(rec)

	_, span := tp.Tracer("test").Start(context.Background(), "labels-probe")
	span.End()

	require.NotNil(t, rec.span)
	labels := getSpanLabels(rec.span)
	assert.Equal(t, prometheus.Labels{
		"span_name": "labels-probe",
		"service":   "svc-only",
		"version":   "", // missing resource attrs become empty labels
		"env":       "",
		"moniker":   "",
	}, labels)
}

type spanCapture struct {
	span sdktrace.ReadOnlySpan
}

func newSpanCapture() *spanCapture { return &spanCapture{} }

func (sc *spanCapture) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {}
func (sc *spanCapture) OnEnd(s sdktrace.ReadOnlySpan)                         { sc.span = s }
func (sc *spanCapture) Shutdown(ctx context.Context) error                    { return nil }
func (sc *spanCapture) ForceFlush(ctx context.Context) error                  { return nil }

func TestRunMetricsApi(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	RunMetricsApi(t.Context(), port, zap.NewNop())

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	var resp *http.Response
	require.Eventually(t, func() bool {
		resp, err = http.Get(url) //nolint:noctx
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "metrics endpoint should come up")
	defer func() { require.NoError(t, resp.Body.Close()) }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
