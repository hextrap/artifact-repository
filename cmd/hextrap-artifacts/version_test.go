package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/edition"
)

// The release build stamps the version in with -ldflags; -version must report
// it without needing a config file, so an operator can check what's installed.
func TestVersionFlagReportsStampedVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	r := require.New(t)
	bin := filepath.Join(t.TempDir(), "hextrap-artifacts")

	build := exec.Command(goBin, "build", "-ldflags", "-X main.version=1.2.3", "-o", bin, ".")
	out, err := build.CombinedOutput()
	r.NoError(err, string(out))

	out, err = exec.Command(bin, "-version", "-config", "/nonexistent/config.yaml").CombinedOutput()
	r.NoError(err, string(out))
	r.Equal("hextrap-artifacts 1.2.3 (self-hosted)", strings.TrimSpace(string(out)))
}

func TestUnstampedBuildSaysDev(t *testing.T) {
	require.Equal(t, "hextrap-artifacts dev ("+edition.Name+")", versionString())
}
