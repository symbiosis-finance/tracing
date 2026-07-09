package tracing

import (
	"runtime"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildInfo verifies that importing the package is enough to expose the
// build_info gauge on the default registry with the expected labels.
func TestBuildInfo(t *testing.T) {
	assert.Equal(t, 1.0, testutil.ToFloat64(
		buildInfo.WithLabelValues(Version, runtime.Version(), vcsRevision())))

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != "build_info" {
			continue
		}
		require.Len(t, mf.GetMetric(), 1)
		labels := map[string]string{}
		for _, lp := range mf.GetMetric()[0].GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		// Tests build without -ldflags, so the version is the notset sentinel.
		assert.Equal(t, VersionNotSet, labels["version"])
		assert.Equal(t, runtime.Version(), labels["go_version"])
		assert.NotEmpty(t, labels["commit"])
		return
	}
	t.Fatal("build_info not found on the default registry")
}
