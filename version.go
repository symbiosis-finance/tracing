package tracing

const VersionNotSet = "notset"

// This var should be set via `go build -ldflags "-X=github.com/symbiosis-finance/tracing.Version=v1.2.3" ...`
var Version string = VersionNotSet
