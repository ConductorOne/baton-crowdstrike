package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

type wantFactor struct {
	desc string
	sev  v2.RiskFactor_Severity
}

func TestPasswordRiskFactors(t *testing.T) {
	tests := []struct {
		name string
		pa   *PasswordAttributes
		want []wantFactor
	}{
		{name: "nil attributes -> none", pa: nil},
		{name: "strong, not exposed -> none", pa: &PasswordAttributes{Exposed: false, Strength: "STRONG"}},
		{name: "unknown strength -> none", pa: &PasswordAttributes{Strength: "UNKNOWN"}},
		{
			name: "exposed -> high",
			pa:   &PasswordAttributes{Exposed: true, Strength: "STRONG"},
			want: []wantFactor{{riskFactorExposedPassword, v2.RiskFactor_SEVERITY_HIGH}},
		},
		{
			name: "weak (case-insensitive) -> medium",
			pa:   &PasswordAttributes{Strength: "weak"},
			want: []wantFactor{{riskFactorWeakPassword, v2.RiskFactor_SEVERITY_MEDIUM}},
		},
		{
			name: "exposed + weak -> both",
			pa:   &PasswordAttributes{Exposed: true, Strength: "WEAK"},
			want: []wantFactor{
				{riskFactorExposedPassword, v2.RiskFactor_SEVERITY_HIGH},
				{riskFactorWeakPassword, v2.RiskFactor_SEVERITY_MEDIUM},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := passwordRiskFactors(AccountData{PasswordAttributes: tt.pa})
			if len(got) != len(tt.want) {
				t.Fatalf("got %d factors, want %d: %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if got[i].GetDescription() != w.desc || got[i].GetSeverity() != w.sev {
					t.Errorf("factor[%d] = (%s, %v), want (%s, %v)",
						i, got[i].GetDescription(), got[i].GetSeverity(), w.desc, w.sev)
				}
			}
		})
	}
}

// TestSecurityInsightResourcePasswordSignal proves an account whose ONLY risk signal
// is a compromised (exposed) password still produces a security insight, and that the
// EXPOSED_PASSWORD risk factor lands on the built resource's trait.
func TestSecurityInsightResourcePasswordSignal(t *testing.T) {
	identity := IdentityRiskData{
		PrimaryDisplayName: "Test User",
		EmailAddresses:     []string{"test.user@example.com"},
		// no entity-level RiskFactors — the only signal is the password
	}
	account := AccountData{
		TypeName:           "ActiveDirectoryAccountDescriptor",
		ObjectGUID:         "682cf9db-abba-432f-b682-5a7fea80a00a", // gives a non-empty ExternalID
		PasswordAttributes: &PasswordAttributes{Exposed: true, Strength: "UNKNOWN"},
	}

	res, err := securityInsightResource(identity, account)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected a security insight resource, got nil")
	}

	var trait v2.SecurityInsightTrait
	annos := annotations.Annotations(res.GetAnnotations())
	if _, err := annos.Pick(&trait); err != nil {
		t.Fatalf("pick security insight trait: %v", err)
	}
	factors := trait.GetRiskScore().GetRiskFactors()
	found := false
	for _, f := range factors {
		if f.GetDescription() == riskFactorExposedPassword && f.GetSeverity() == v2.RiskFactor_SEVERITY_HIGH {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an %s (HIGH) risk factor on the insight, got %+v", riskFactorExposedPassword, factors)
	}
}
