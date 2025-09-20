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

func Map[T, U any](seq iter.Seq[T], f func(T) U) iter.Seq[U] {
	return func(yield func(U) bool) {
		for a := range seq {
			if !yield(f(a)) {
				return
			}
		}
	}
}

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

type TracerLogsConfig struct {
	EnableResourceAttrs    bool
	EnableParentSpanAttrs  bool
	EnableSpanContextAttrs bool
}

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

func DefaultTracerConfig() (cfg TracerConfig) {
	cfg.LogFilters.EnableSpanContextAttrs = true
	return
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

func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if deadline, ok := ctx.Deadline(); ok {
		opts = append(opts, trace.WithAttributes(attribute.Stringer("context_timeout", time.Until(deadline))))
	}
	return Tracer().Start(ctx, spanName, opts...)
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

// Store trace attributes from ctx to MapCarrier
func StoreTrace(ctx context.Context) (m propagation.MapCarrier) {
	m = make(propagation.MapCarrier)
	otel.GetTextMapPropagator().Inject(ctx, m)
	return
}

// Load trace attributes from MapCarrier to returned context
func LoadTrace(ctx context.Context, m propagation.MapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, m)
}

func ErrorAttr(key string, err error) (attr attribute.KeyValue) {
	if err != nil {
		return attribute.Key(key).String(err.Error())
	}
	return
}

func StringerSlice[T fmt.Stringer](k string, values []T) (attr attribute.KeyValue) {
	vals := make([]string, len(values))
	for i, v := range values {
		vals[i] = v.String()
	}
	return attribute.StringSlice(k, vals)
}
