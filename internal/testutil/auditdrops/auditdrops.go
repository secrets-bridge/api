// Package auditdrops lets a test package assert, at the end of its run,
// that no real audit writer lost metadata to the allowlist in
// pkg/storage (api#279). It reads the drop counter instead of the log,
// so a test that swaps the default logger can't hide a drop.
package auditdrops

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/secrets-bridge/api/pkg/storage"
)

// FixturePrefix marks an action written on purpose with keys the
// allowlist refuses (canary and shape tests). Drops under it are
// expected and not reported.
const FixturePrefix = "test."

// Main runs the package's tests, then fails the run if any action not
// under FixturePrefix had a key dropped or rejected. Use it as
//
//	func TestMain(m *testing.M) { os.Exit(auditdrops.Main(m)) }
func Main(m *testing.M) int {
	storage.ResetAuditMetadataDrops()
	code := m.Run()
	if n := Report(os.Stderr, storage.AuditMetadataDrops()); n > 0 && code == 0 {
		return 1
	}
	return code
}

// Report writes every non-fixture drop to w, sorted, and returns how
// many distinct (action, key, reason) entries it found.
func Report(w io.Writer, drops map[storage.AuditMetadataDrop]int) int {
	var lines []string
	for d, n := range drops {
		if strings.HasPrefix(d.Action, FixturePrefix) {
			continue
		}
		lines = append(lines, fmt.Sprintf("  action=%s key=%s reason=%s count=%d", d.Action, d.Key, d.Reason, n))
	}
	if len(lines) == 0 {
		return 0
	}
	sort.Strings(lines)
	_, _ = fmt.Fprintf(w, "FAIL: audit metadata dropped by the allowlist (add the key to auditMetaKeys with the right kind, or fix the writer):\n%s\n",
		strings.Join(lines, "\n"))
	return len(lines)
}
