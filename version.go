package tracing

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

const VersionNotSet = "notset"

// This var should be set via `go build -ldflags "-X=github.com/symbiosis-finance/tracing.Version=v1.2.3" ...`
var Version string = VersionNotSet

func VersionAttr() attribute.KeyValue {
	return semconv.ServiceVersion(Version)
}
