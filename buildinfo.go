package tracing

import (
	"runtime"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// buildInfo exposes the service's build metadata as a constant-1 gauge, so the
// running version — and, via the series appearing/disappearing over time, the
// upgrade history — is visible in Prometheus/Grafana for every service that
// imports this module. One series per process:
//   - version:    service version (Version, set with -ldflags -X)
//   - go_version: Go runtime that built the binary
//   - commit:     VCS revision embedded by the Go toolchain (-buildvcs)
//
// The metric is deliberately named build_info with no service prefix: the
// service identity comes from the scrape labels (service/job/moniker/…), so a
// single fleet-wide query covers every symbiosis service.
var buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "build_info",
	Help: "Service build metadata; constant 1. Labels: version, go_version, commit.",
}, []string{"version", "go_version", "commit"})

// init populates the gauge at package load: Version is injected at link time,
// so it is already final here, and promauto registers with the default
// registry that RunMetricsApi serves — any binary importing tracing exports
// build_info with no extra wiring.
func init() {
	buildInfo.WithLabelValues(Version, runtime.Version(), vcsRevision()).Set(1)
}

// vcsRevision returns the git commit the binary was built from, or "unknown"
// if the toolchain did not embed VCS info (e.g. built with -buildvcs=false or
// outside a git checkout).
func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return "unknown"
}
