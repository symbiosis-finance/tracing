package tracing

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"time"

	"github.com/nikicat/tryerr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

func reverseLookupHostname(ctx context.Context) (rHost string, err error) {
	defer tryerr.Catch(&err)
	host := tryerr.Try(os.Hostname()).Err("failed to obtain hostname")
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	addrs := tryerr.Try(net.DefaultResolver.LookupIPAddr(ctx, host)).Err("failed to lookup ip addr")
	rHosts := tryerr.Try(net.DefaultResolver.LookupAddr(ctx, addrs[0].String())).Err("failed to reverse lookup host")
	rHost = rHosts[0]
	return
}

func attributes(attrs ...attribute.KeyValue) []attribute.KeyValue {
	return attrs
}

func newTraceProvider(ctx context.Context, exp sdktrace.SpanExporter, cfg TracerConfig, serviceName, version string, logger *zap.Logger) (tp *sdktrace.TracerProvider) {
	hostname, err := reverseLookupHostname(ctx)
	if err != nil {
		logger.Warn("failed to reverse resolve hostname", zap.Error(err))
		hostname = tryerr.Must(os.Hostname())
	}
	attrs := attributes(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
		attribute.String("symbiosis-finance.moniker", os.Getenv("REL_SYMBIOSIS_MONIKER")),
		semconv.HostName(hostname),
	)
	r := tryerr.Must(resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	))

	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(r),
	}
	if exp != nil {
		options = append(options, sdktrace.WithBatcher(exp))
	}
	if cfg.EnableLogs {
		options = append(options, sdktrace.WithSpanProcessor(newLoggingSpanProcessor(logger)))
	}
	if cfg.EnableMetrics {
		options = append(options, sdktrace.WithSpanProcessor(newMetricsSpanProcessor()))
	}
	tp = sdktrace.NewTracerProvider(options...)
	logger.Info("tracing initialized", zap.Any("config", cfg), zap.String("hostname", hostname))
	return
}

type TracerConfig struct {
	// Only one is used
	EnableStdout  bool
	EnableLogs    bool
	EnableMetrics bool
	MetricsPort   int
	GrpcUrl       string
	HttpUrl       string
}

func DefaultTracerConfig() TracerConfig {
	return TracerConfig{}
}

func (cfg TracerConfig) GetTracingConfig() TracerConfig {
	return cfg
}

func basicAuthOption(httpUrl string) otlptracehttp.Option {
	u := tryerr.Must(url.Parse(httpUrl))
	if u.User == nil {
		return nil
	}
	return otlptracehttp.WithHeaders(map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String())),
	})
}

func InitTracer(ctx context.Context, cfg TracerConfig, serviceName, version string, logger *zap.Logger) {
	var exp sdktrace.SpanExporter
	if cfg.EnableStdout {
		exp = tryerr.Must(stdouttrace.New())
	} else if cfg.GrpcUrl != "" {
		exp = tryerr.Must(otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(cfg.GrpcUrl)))
	} else if cfg.HttpUrl != "" {
		options := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(cfg.HttpUrl)}
		if auth := basicAuthOption(cfg.HttpUrl); auth != nil {
			options = append(options, auth)
		}
		exp = tryerr.Must(otlptracehttp.New(ctx, options...))
	}
	if cfg.MetricsPort != 0 {
		RunMetricsApi(ctx, cfg.MetricsPort, logger)
	}
	tp := newTraceProvider(ctx, exp, cfg, serviceName, version, logger)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
}

func ShutdownTracer() {
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		// This operation could block
		timeoutCtx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
		defer cancel()
		_ = tp.Shutdown(timeoutCtx)
	}
}

var defaultTracerName string = "github.com/symbiosis-finance/tracing"

func Tracer() trace.Tracer {
	return otel.Tracer(defaultTracerName)
}

func TrackError(span trace.Span, err error) {
	span.RecordError(err)
	if err == nil {
		span.SetStatus(codes.Ok, "")
	} else {
		span.SetStatus(codes.Error, err.Error())
	}
}

func EndSpan(span trace.Span, err *error, attributes ...attribute.KeyValue) {
	if err != nil {
		TrackError(span, *err)
	}
	span.SetAttributes(attributes...)
	span.End()
}

func NilStringer(name string, s fmt.Stringer) attribute.KeyValue {
	if isNil(s) {
		return attribute.String(name, "<nil>")
	} else {
		return attribute.Stringer(name, s)
	}
}

func isNil(i any) bool {
	iv := reflect.ValueOf(i)
	if !iv.IsValid() {
		return true
	}
	switch iv.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Map, reflect.Func, reflect.Interface:
		return iv.IsNil()
	default:
		return false
	}
}

func StoreTrace(ctx context.Context) (m propagation.MapCarrier) {
	m = make(propagation.MapCarrier)
	otel.GetTextMapPropagator().Inject(ctx, m)
	return
}

func LoadTrace(ctx context.Context, m propagation.MapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, m)
}

func ErrorAttr(key string, err error) (attr attribute.KeyValue) {
	if err != nil {
		return attribute.Key(key).String(err.Error())
	}
	return
}
