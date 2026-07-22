package connector

import (
	"strings"
	"testing"
)

// TestBuildIdentityRiskQuery verifies password-risk ingestion is opt-in: the
// passwordAttributes selection is present only when explicitly enabled, and the
// base risk query is intact either way.
func TestBuildIdentityRiskQuery(t *testing.T) {
	off := buildIdentityRiskQuery(false)
	if strings.Contains(off, "passwordAttributes") {
		t.Errorf("password risk OFF (default): query must not request passwordAttributes:\n%s", off)
	}

	on := buildIdentityRiskQuery(true)
	if !strings.Contains(on, "passwordAttributes") {
		t.Errorf("password risk ON: query must request passwordAttributes:\n%s", on)
	}

	// The base entities query must be intact regardless of the flag.
	for _, q := range []string{off, on} {
		for _, want := range []string{"GetIdentityRiskScores", "riskScore", "riskFactors", "ActiveDirectoryAccountDescriptor"} {
			if !strings.Contains(q, want) {
				t.Errorf("query missing base field %q:\n%s", want, q)
			}
		}
	}
}
