package tracing

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type loggingSpanProcessor struct {
	startLogger *zap.Logger
	endLogger   *zap.Logger
}

var _ sdktrace.SpanProcessor = loggingSpanProcessor{}

func newLoggingSpanProcessor(logger *zap.Logger) loggingSpanProcessor {
	return loggingSpanProcessor{
		startLogger: logger.WithOptions(zap.AddCallerSkip(3)),
		endLogger:   logger.WithOptions(zap.AddCallerSkip(3)),
	}
}

func GetLogFields(ctx context.Context) []attribute.KeyValue {
	if v := ctx.Value(ctxAttributeKey); v != nil {
		return v.([]attribute.KeyValue)
	}
	return nil
}

func AddLogFields(ctx context.Context, fields ...attribute.KeyValue) context.Context {
	return context.WithValue(ctx, ctxAttributeKey, append(GetLogFields(ctx), fields...))
}

func (lsp loggingSpanProcessor) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {
	if fields := GetLogFields(ctx); fields != nil {
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
	var level zapcore.Level
	if s.Status().Code == codes.Error {
		level = zapcore.ErrorLevel
	} else {
		level = zapcore.DebugLevel
	}
	for _, ev := range s.Events() {
		lsp.endLogger.WithOptions(zap.WithClock(zapClock{ev.Time})).Log(level, ev.Name+" "+s.Name(), eventToZapFields(s, ev)...)
	}
	lsp.endLogger.Log(level, "end "+s.Name(), spanToZapFields(s)...)
}

func (lsp loggingSpanProcessor) Shutdown(ctx context.Context) error   { return nil }
func (lsp loggingSpanProcessor) ForceFlush(ctx context.Context) error { return nil }

func AttributeToZapField(attr attribute.KeyValue) zap.Field {
	if !attr.Valid() {
		return zap.Skip()
	}
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

func attributesToZapFields(attrs ...attribute.KeyValue) (fields []zap.Field) {
	for _, attr := range attrs {
		fields = append(fields, AttributeToZapField(attr))
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
	fields = append(fields, resourceToZapFields(s.Resource())...)
	fields = append(fields, zap.Stringer("span.kind", s.SpanKind()))
	fields = append(fields, spanContextToZapFields(s.Parent(), "parent")...)
	return append(fields, attributesToZapFields(s.Attributes()...)...)
}

func eventToZapFields(s sdktrace.ReadOnlySpan, ev sdktrace.Event) (fields []zap.Field) {
	fields = spanContextToZapFields(s.SpanContext(), "span")
	fields = append(fields, attributesToZapFields(ev.Attributes...)...)
	fields = append(fields, attributesToZapFields(s.Attributes()...)...)
	return
}

func resourceToZapFields(r *resource.Resource) (fields []zap.Field) {
	it := r.Iter()
	for it.Next() {
		attr := it.Attribute()
		if strings.HasPrefix(string(attr.Key), "telemetry.") {
			// telemetry.* attrs are not very useful in logs.
			continue
		}
		fields = append(fields, AttributeToZapField(attr))
	}
	return
}

func DefaultZapFields() []zap.Field {
	return attributesToZapFields(
		VersionAttr(),
		AppEnvFromEnv(),
		MonikerAttrFromEnv(),
		ServiceNameFromEnv(),
	)
}
