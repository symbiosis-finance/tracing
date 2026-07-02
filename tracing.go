// Package tracing provides an opinionated OpenTelemetry tracing setup for Go
// services: one-call initialization with OTLP (gRPC/HTTP) or stdout export,
// mirroring of spans to zap logs, Prometheus span metrics, automatic resource
// attributes, and typed attribute constructors for blockchain semantics.
//
// Typical usage:
//
//	tracing.InitTracer(ctx, cfg, logger)
//	defer tracing.ShutdownTracer()
//
//	func doWork(ctx context.Context) (err error) {
//		ctx, span := tracing.StartSpan(ctx, "doWork")
//		defer tracing.EndSpan(span, &err)
//		// ...
//	}
package tracing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net"
	"net/url"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/nikicat/tryerr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var errLookupTimeout = errors.New("hostname lookup timeout")

func reverseLookupHostname(ctx context.Context) (rHost string, err error) {
	defer tryerr.Catch(&err)
	host := tryerr.Try(os.Hostname()).Err("failed to obtain hostname")
	ctx, cancel := context.WithTimeoutCause(ctx, time.Second, errLookupTimeout)
	defer cancel()
	addrs := tryerr.Try(net.DefaultResolver.LookupIPAddr(ctx, host)).Err("failed to lookup ip addr")
	rHosts := tryerr.Try(net.DefaultResolver.LookupAddr(ctx, addrs[0].String())).Err("failed to reverse lookup host")
	rHost = rHosts[0]
	return
}

type attrMap map[attribute.Key]attribute.KeyValue

func addAttrIfAbsent(attrs attrMap, newAttr attribute.KeyValue) {
	if existingAttr, ok := attrs[newAttr.Key]; (!ok || !existingAttr.Valid()) && newAttr.Valid() {
		attrs[newAttr.Key] = newAttr
	}
}

func newTraceProvider(ctx context.Context, exp sdktrace.SpanExporter, cfg TracerConfig, logger *zap.Logger, resourceAttrs []attribute.KeyValue) (tp *sdktrace.TracerProvider) {
	attrs := make(attrMap, len(resourceAttrs))
	for _, attr := range resourceAttrs {
		attrs[attr.Key] = attr
	}
	if attr, ok := attrs[semconv.HostNameKey]; !ok || !attr.Valid() {
		hostname, err := reverseLookupHostname(ctx)
		if err != nil {
			logger.Warn("failed to reverse resolve hostname", zap.Error(err))
			hostname = tryerr.Must(os.Hostname())
		}
		attrs[semconv.HostNameKey] = semconv.HostName(hostname)
	}
	addAttrIfAbsent(attrs, semconv.ServiceInstanceID(uuid.NewString()))
	addAttrIfAbsent(attrs, semconv.TelemetrySDKName("opentelemetry"))
	addAttrIfAbsent(attrs, semconv.TelemetrySDKLanguageGo)
	addAttrIfAbsent(attrs, semconv.TelemetrySDKVersion(sdk.Version()))
	addAttrIfAbsent(attrs, semconv.ProcessCommand(os.Args[0]))
	addAttrIfAbsent(attrs, VersionAttr())
	addAttrIfAbsent(attrs, MonikerAttrFromEnv())
	addAttrIfAbsent(attrs, AppEnvFromEnv())
	addAttrIfAbsent(attrs, ServiceNameFromEnv())
	attrSlice := slices.Collect(maps.Values(attrs))
	r := resource.NewWithAttributes(semconv.SchemaURL, attrSlice...)

	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(r),
	}
	if exp != nil {
		options = append(options, sdktrace.WithBatcher(exp))
	}
	if cfg.EnableLogs {
		options = append(options, sdktrace.WithSpanProcessor(newLoggingSpanProcessor(logger, cfg.LogFilters)))
	}
	if cfg.EnableMetrics {
		options = append(options, sdktrace.WithSpanProcessor(newMetricsSpanProcessor()))
	}
	if len(cfg.SpanBlacklist) > 0 {
		options = append(options, sdktrace.WithSampler(filteringSampler{
			blacklistedSpans: maps.Collect(Map2(slices.Values(cfg.SpanBlacklist), func(s string) (string, any) { return s, nil })),
		}))
	}
	tp = sdktrace.NewTracerProvider(options...)
	fields := append([]zap.Field{zap.Reflect("config", cfg)}, attributesToZapFields(attrSlice...)...)
	logger.Info("tracing initialized", fields...)
	return
}

// Map returns an iterator that yields f applied to every element of seq.
func Map[T, U any](seq iter.Seq[T], f func(T) U) iter.Seq[U] {
	return func(yield func(U) bool) {
		for a := range seq {
			if !yield(f(a)) {
				return
			}
		}
	}
}

// Map2 returns a key-value iterator that yields f applied to every element of seq.
func Map2[T, U, V any](seq iter.Seq[T], f func(T) (U, V)) iter.Seq2[U, V] {
	return func(yield func(U, V) bool) {
		for a := range seq {
			if !yield(f(a)) {
				return
			}
		}
	}
}

type filteringSampler struct {
	blacklistedSpans map[string]any // list of spans to filter out
}

func (fs filteringSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	if _, ok := fs.blacklistedSpans[p.Name]; ok {
		return sdktrace.SamplingResult{
			Decision:   sdktrace.Drop,
			Tracestate: trace.SpanContextFromContext(p.ParentContext).TraceState(),
		}
	} else {
		return sdktrace.SamplingResult{
			Decision:   sdktrace.RecordAndSample,
			Tracestate: trace.SpanContextFromContext(p.ParentContext).TraceState(),
		}
	}
}

func (s filteringSampler) Description() string {
	return "FilteringSampler"
}

// TracerLogsConfig selects which extra fields the logging span processor
// attaches to every span log line.
type TracerLogsConfig struct {
	EnableResourceAttrs    bool // resource attributes (except telemetry.*)
	EnableParentSpanAttrs  bool // parent trace/span IDs
	EnableSpanContextAttrs bool // own trace/span IDs
}

// TracerConfig configures the tracer provider created by InitTracer.
type TracerConfig struct {
	// Only one of outputs is used
	EnableStdout bool
	GrpcUrl      string
	HttpUrl      string

	EnableLogs    bool // Enable logging of span's start/end
	LogFilters    TracerLogsConfig
	EnableMetrics bool     // Enable span metrics
	MetricsPort   int      // Port to expose metrics on
	SpanBlacklist []string // List of spans to filter out
}

// DefaultTracerConfig returns a config with span context attributes enabled
// in log lines and everything else disabled.
func DefaultTracerConfig() (cfg TracerConfig) {
	cfg.LogFilters.EnableSpanContextAttrs = true
	return
}

// GetTracingConfig returns the config itself, letting TracerConfig be embedded
// in a larger service config and passed around behind an interface.
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

// InitTracer builds the exporter selected by cfg (stdout, OTLP gRPC, or OTLP
// HTTP — checked in that order), registers a global tracer provider with the
// configured span processors, and installs a composite W3C TraceContext +
// Baggage propagator. Explicitly passed resourceAttrs take precedence over the
// automatically detected ones (hostname, service instance ID, version, and
// SERVICE/APP_ENV/MONIKER environment variables). If cfg.MetricsPort is
// non-zero, an HTTP server exposing Prometheus metrics on /metrics is started
// and shut down when ctx is cancelled.
func InitTracer(ctx context.Context, cfg TracerConfig, logger *zap.Logger, resourceAttrs ...attribute.KeyValue) {
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
	tp := newTraceProvider(ctx, exp, cfg, logger, resourceAttrs)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}

// ShutdownTracer flushes and shuts down the global tracer provider installed
// by InitTracer, waiting at most one second.
func ShutdownTracer() {
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		// This operation could block
		timeoutCtx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
		defer cancel()
		_ = tp.Shutdown(timeoutCtx)
	}
}

var defaultTracerName string = "github.com/symbiosis-finance/tracing"

// Tracer returns the package-level tracer from the global tracer provider.
func Tracer() trace.Tracer {
	return otel.Tracer(defaultTracerName)
}

// TrackError records err on the span and sets the span status: Error with the
// error message for a non-nil err, Ok otherwise.
func TrackError(span trace.Span, err error) {
	span.RecordError(err)
	if err == nil {
		span.SetStatus(codes.Ok, "")
	} else {
		span.SetStatus(codes.Error, err.Error())
	}
}

// StartSpan starts a span using the package-level tracer. If ctx carries a
// deadline, the remaining time is recorded as a context_timeout attribute.
// Pair it with EndSpan:
//
//	ctx, span := tracing.StartSpan(ctx, "operation")
//	defer tracing.EndSpan(span, &err)
func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if deadline, ok := ctx.Deadline(); ok {
		opts = append(opts, trace.WithAttributes(attribute.Stringer("context_timeout", time.Until(deadline))))
	}
	return Tracer().Start(ctx, spanName, opts...)
}

// EndSpan sets the given attributes and ends the span. If err is non-nil it is
// dereferenced at call time (so it works with named returns in a defer) and
// recorded via TrackError, setting the span status accordingly.
func EndSpan(span trace.Span, err *error, attributes ...attribute.KeyValue) {
	if err != nil {
		TrackError(span, *err)
	}
	span.SetAttributes(attributes...)
	span.End()
}

// NilStringer is like attribute.Stringer but safe for nil values: instead of
// panicking on a nil s it produces the string "<nil>".
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
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Func, reflect.Interface:
		return iv.IsNil()
	default:
		return false
	}
}

// StoreTrace injects the trace context and baggage from ctx into a MapCarrier
// using the global propagator, for transports without header support (message
// queues, persisted jobs). Restore it on the consuming side with LoadTrace.
func StoreTrace(ctx context.Context) (m propagation.MapCarrier) {
	m = make(propagation.MapCarrier)
	otel.GetTextMapPropagator().Inject(ctx, m)
	return
}

// LoadTrace extracts the trace context and baggage stored by StoreTrace from
// the carrier and returns a context carrying them.
func LoadTrace(ctx context.Context, m propagation.MapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, m)
}

// ErrorAttr returns a string attribute holding the error message, or an
// invalid (skipped) attribute if err is nil.
func ErrorAttr(key string, err error) (attr attribute.KeyValue) {
	if err != nil {
		return attribute.Key(key).String(err.Error())
	}
	return
}

// StringerSlice returns a string-slice attribute with the String() rendering
// of every element of values.
func StringerSlice[T fmt.Stringer](k string, values []T) (attr attribute.KeyValue) {
	vals := make([]string, len(values))
	for i, v := range values {
		vals[i] = v.String()
	}
	return attribute.StringSlice(k, vals)
}
