// Package baggage propagates a request identifier across service boundaries
// via W3C Baggage, so it survives process hops wherever the OpenTelemetry
// propagator is installed (see tracing.InitTracer).
package baggage

import (
	"context"

	"go.opentelemetry.io/otel/baggage"
)

const requestIDKey = "request.id"

// WithRequestID returns a context whose baggage carries the given request ID,
// preserving any other baggage members already present. If id is not a valid
// baggage value, ctx is returned unchanged.
func WithRequestID(ctx context.Context, id string) context.Context {
	member, err := baggage.NewMember(requestIDKey, id)
	if err != nil {
		return ctx
	}

	return contextWithMember(ctx, member)
}

// RequestIDFromContext returns the request ID from the context's baggage, or
// an empty string if none is set.
func RequestIDFromContext(ctx context.Context) string {
	return baggage.FromContext(ctx).Member(requestIDKey).Value()
}

func contextWithMember(ctx context.Context, member baggage.Member) context.Context {
	bag, err := baggage.FromContext(ctx).SetMember(member)
	if err != nil {
		return ctx
	}

	return baggage.ContextWithBaggage(ctx, bag)
}
