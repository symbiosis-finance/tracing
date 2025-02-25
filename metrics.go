package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

var spanLabels = []string{"span_name", "service", "moniker", "version"}

func getSpanLabels(s sdktrace.ReadOnlySpan) prometheus.Labels {
	attrs := s.Resource().Attributes()
	attrMap := make(map[attribute.Key]attribute.Value, len(attrs))
	for _, attr := range attrs {
		attrMap[attr.Key] = attr.Value
	}
	return prometheus.Labels{
		"span_name": s.Name(),
		"service":   attrMap["service.name"].AsString(),
		"moniker":   attrMap["symbiosis-finance.moniker"].AsString(),
		"version":   attrMap["service.version"].AsString(),
	}
}

var spanStarted = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tracing_span_started",
	Help: "Started span count",
}, spanLabels)

var spanEnded = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tracing_span_ended",
	Help: "Ended span count",
}, spanLabels)

var spanSucceeded = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tracing_span_succeeded",
	Help: "Succeeded span count",
}, spanLabels)

var spanFailed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tracing_span_failed",
	Help: "Failed span count",
}, spanLabels)

var spanCurrent = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tracing_span_current",
	Help: "Current span count",
}, spanLabels)

type metricsSpanProcessor struct{}

var _ sdktrace.SpanProcessor = metricsSpanProcessor{}

func newMetricsSpanProcessor() metricsSpanProcessor {
	return metricsSpanProcessor{}
}

func (metricsSpanProcessor) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {
	labels := getSpanLabels(s)
	spanStarted.With(labels).Inc()
	spanCurrent.With(labels).Inc()
}

func (metricsSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	labels := getSpanLabels(s)
	spanEnded.With(labels).Inc()
	spanCurrent.With(labels).Dec()
	switch s.Status().Code {
	case codes.Ok:
		spanSucceeded.With(labels).Inc()
	case codes.Error:
		spanFailed.With(labels).Inc()
	}
}

func (metricsSpanProcessor) Shutdown(ctx context.Context) error   { return nil }
func (metricsSpanProcessor) ForceFlush(ctx context.Context) error { return nil }

func RunMetricsApi(ctx context.Context, port int, logger *zap.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
	}
	logger.Info("Create the monitoring", zap.Int("port", port))
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("err run monitoring", zap.Error(err))
			return
		}
	}()
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("err shutdown monitoring", zap.Error(err))
			return
		}
		logger.Info("monitoring shutdown from context")
	}()
}
