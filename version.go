package tracing

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

// VersionNotSet is the Version value when no version was injected at build time.
const VersionNotSet = "notset"

// Version is the service version reported as the service.version resource
// attribute. It should be set at build time:
//
//	go build -ldflags "-X=github.com/symbiosis-finance/tracing.Version=v1.2.3" ...
var Version string = VersionNotSet

// VersionAttr returns the service.version attribute holding Version.
func VersionAttr() attribute.KeyValue {
	return semconv.ServiceVersion(Version)
}
