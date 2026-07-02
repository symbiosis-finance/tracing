package baggage

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/baggage"
)

func TestWithRequestID(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-1")
	if got := RequestIDFromContext(ctx); got != "req-1" {
		t.Errorf("RequestIDFromContext() = %q, want %q", got, "req-1")
	}
}

func TestWithRequestIDPreservesExistingMembers(t *testing.T) {
	member, err := baggage.NewMember("tenant.id", "acme")
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	ctx := baggage.ContextWithBaggage(context.Background(), bag)

	ctx = WithRequestID(ctx, "req-2")

	if got := RequestIDFromContext(ctx); got != "req-2" {
		t.Errorf("RequestIDFromContext() = %q, want %q", got, "req-2")
	}
	if got := baggage.FromContext(ctx).Member("tenant.id").Value(); got != "acme" {
		t.Errorf("existing member tenant.id = %q, want %q", got, "acme")
	}
}

func TestWithRequestIDOverwritesPreviousValue(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-old")
	ctx = WithRequestID(ctx, "req-new")
	if got := RequestIDFromContext(ctx); got != "req-new" {
		t.Errorf("RequestIDFromContext() = %q, want %q", got, "req-new")
	}
}
