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
	"go.uber.org/zap/zapcore"
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

type loggingSpanProcessor struct {
	startLogger *zap.Logger
	endLogger   *zap.Logger
}

var _ sdktrace.SpanProcessor = loggingSpanProcessor{}

func newLoggingSpanProcessor(logger *zap.Logger) loggingSpanProcessor {
	return loggingSpanProcessor{
		startLogger: logger.WithOptions(zap.AddCallerSkip(2)),
		endLogger:   logger.WithOptions(zap.AddCallerSkip(3)),
	}
}

func getLogFields(ctx context.Context) []attribute.KeyValue {
	if v := ctx.Value(ctxAttributeKey); v != nil {
		return v.([]attribute.KeyValue)
	}
	return nil
}

func AddLogFields(ctx context.Context, fields ...attribute.KeyValue) context.Context {
	return context.WithValue(ctx, ctxAttributeKey, append(getLogFields(ctx), fields...))
}

func (lsp loggingSpanProcessor) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {
	if fields := getLogFields(ctx); fields != nil {
		s.SetAttributes(append(fields, s.Attributes()...)...)
	}
	lsp.startLogger.Debug("start "+s.Name(), spanToZapFields(s)...)
}

type zapClock struct {
	t time.Time
}

var _ zapcore.Clock = zapClock{}

func (zc zapClock) Now() time.Time {
	return zc.t
}

func (zc zapClock) NewTicker(d time.Duration) *time.Ticker {
	return time.NewTicker(d)
}

func (lsp loggingSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	for _, ev := range s.Events() {
		lsp.endLogger.WithOptions(zap.WithClock(zapClock{ev.Time})).Debug(ev.Name, eventToZapFields(s, ev)...)
	}
	lsp.endLogger.Debug("end "+s.Name(), spanToZapFields(s)...)
}

func (lsp loggingSpanProcessor) Shutdown(ctx context.Context) error   { return nil }
func (lsp loggingSpanProcessor) ForceFlush(ctx context.Context) error { return nil }

func attributeToZapField(attr attribute.KeyValue) zap.Field {
	key := string(attr.Key)
	value := attr.Value
	switch value.Type() {
	case attribute.BOOL:
		return zap.Bool(key, value.AsBool())
	case attribute.INT64:
		return zap.Int64(key, value.AsInt64())
	case attribute.FLOAT64:
		return zap.Float64(key, value.AsFloat64())
	case attribute.STRING:
		return zap.String(key, value.AsString())
	case attribute.BOOLSLICE:
		return zap.Bools(key, value.AsBoolSlice())
	case attribute.INT64SLICE:
		return zap.Int64s(key, value.AsInt64Slice())
	case attribute.FLOAT64SLICE:
		return zap.Float64s(key, value.AsFloat64Slice())
	case attribute.STRINGSLICE:
		return zap.Strings(key, value.AsStringSlice())
	default:
		panic(fmt.Errorf("invalid type %d", value.Type()))
	}
}

func attributesToZapFields(attrs []attribute.KeyValue) (fields []zap.Field) {
	for _, attr := range attrs {
		fields = append(fields, attributeToZapField(attr))
	}
	return
}

type ctxAttribute struct{}

var ctxAttributeKey ctxAttribute

func spanContextToZapFields(spanCtx trace.SpanContext, prefix string) []zap.Field {
	return []zap.Field{
		zap.Stringer(prefix+".traceID", spanCtx.TraceID()),
		zap.Stringer(prefix+".ID", spanCtx.SpanID()),
	}
}

func spanToZapFields(s sdktrace.ReadOnlySpan) []zap.Field {
	fields := spanContextToZapFields(s.SpanContext(), "span")
	if s.Status().Code == codes.Error {
		fields = append(fields, zap.String("span.error", s.Status().Description))
	}
	fields = append(fields, zap.Stringer("span.kind", s.SpanKind()))
	fields = append(fields, spanContextToZapFields(s.Parent(), "parent")...)
	return append(fields, attributesToZapFields(s.Attributes())...)
}

func eventToZapFields(s sdktrace.ReadOnlySpan, ev sdktrace.Event) (fields []zap.Field) {
	fields = spanContextToZapFields(s.SpanContext(), "span")
	fields = append(fields, attributesToZapFields(ev.Attributes)...)
	fields = append(fields, attributesToZapFields(s.Attributes())...)
	return
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
	tp = sdktrace.NewTracerProvider(options...)
	logger.Info("tracing initialized", zap.Any("config", cfg), zap.String("hostname", hostname))
	return
}

type TracerConfig struct {
	// Only one is used
	EnableStdout bool
	EnableLogs   bool
	GrpcUrl      string
	HttpUrl      string
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
