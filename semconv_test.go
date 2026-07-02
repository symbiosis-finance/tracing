package tracing

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

func TestChainAttributes(t *testing.T) {
	assert.Equal(t, attribute.Int64("chain.id", 56), ChainID(56))
	assert.Equal(t, attribute.String("chain.name", "bsc"), ChainName("bsc"))
	assert.Equal(t, attribute.Int64("chain.block_number", 12345), BlockNumber(12345))
	assert.Equal(t, attribute.String("chain.block_hash", "1s"), BlockHash(time.Second))
	assert.Equal(t, attribute.String("chain.transaction_id", "1m0s"), TransactionID(time.Minute))
	assert.Equal(t, attribute.Int("chain.log_index", 7), LogIndex(7))
}

func TestIdentityAttributes(t *testing.T) {
	assert.Equal(t, attribute.String("moniker", "node-1"), Moniker("node-1"))
	assert.Equal(t, attribute.String("request.id", "req-9"), RequestID("req-9"))
}

func TestAttributeFromEnv(t *testing.T) {
	t.Setenv("TRACING_TEST_ENV_VAR", "set-value")
	attr := AttributeFromEnv(attribute.Key("test.key"), "TRACING_TEST_ENV_VAR")
	assert.Equal(t, attribute.String("test.key", "set-value"), attr)

	// t.Setenv above guarantees the original value is restored afterwards
	assert.NoError(t, os.Unsetenv("TRACING_TEST_ENV_VAR"))
	attr = AttributeFromEnv(attribute.Key("test.key"), "TRACING_TEST_ENV_VAR")
	assert.False(t, attr.Valid(), "missing env var should produce invalid attribute")
}

func TestEnvAttributeConstructors(t *testing.T) {
	t.Setenv("MONIKER", "moniker-env")
	t.Setenv("APP_ENV", "app-env")
	t.Setenv("SERVICE", "service-env")

	assert.Equal(t, Moniker("moniker-env"), MonikerAttrFromEnv())
	assert.Equal(t, semconv.ServiceNamespace("app-env"), AppEnvFromEnv())
	assert.Equal(t, semconv.ServiceName("service-env"), ServiceNameFromEnv())
}

func TestVersionAttr(t *testing.T) {
	assert.Equal(t, semconv.ServiceVersion(Version), VersionAttr())
	assert.Equal(t, VersionNotSet, Version, "Version should default to notset without ldflags")
}
