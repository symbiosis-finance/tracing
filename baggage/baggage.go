package baggage

import (
	"context"

	"go.opentelemetry.io/otel/baggage"
)

const requestIDKey = "request.id"

func WithRequestID(ctx context.Context, id string) context.Context {
	member, err := baggage.NewMember(requestIDKey, id)
	if err != nil {
		return ctx
	}

	return contextWithMember(ctx, member)
}

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
