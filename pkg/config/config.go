package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	ClientIdField = field.StringField(
		"crowdstrike-client-id",
		field.WithDisplayName("Client ID"),
		field.WithDescription("The CrowdStrike client ID used to generate the access token."),
		field.WithRequired(true),
	)
	ClientSecretField = field.StringField(
		"crowdstrike-client-secret",
		field.WithDisplayName("Client Secret"),
		field.WithIsSecret(true),
		field.WithDescription("The CrowdStrike client secret used to generate the access token."),
		field.WithRequired(true),
	)
	RegionField = field.SelectField(
		"region",
		[]string{"us-1", "us-2", "eu-1", "us-gov-1"},
		field.WithDisplayName("Region"),
		field.WithDescription("CrowdStrike region to connect to."),
		field.WithDefaultValue("us-1"),
	)
	BaseURLField = field.StringField(
		"base-url",
		field.WithDescription("Override the CrowdStrike API URL (for testing)"),
		field.WithHidden(true),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	// Password risk is an enrichment on security_insight rows (non-destructive filter),
	// not a resource-type on/off switch. Optional types are gated by C1 OptInRequired.
	IngestPasswordRiskField = field.BoolField(
		"crowdstrike-ingest-password-risk",
		field.WithDisplayName("Ingest identity password risk"),
		field.WithDescription("Opt-in. When enabled, surface Identity Protection password risk on identity insights — a compromised "+
			"(exposed) password as an EXPOSED_PASSWORD risk factor and a weak password as a WEAK_PASSWORD risk factor. "+
			"Off by default; uses the same Identity Protection scopes as risk score ingestion."),
		field.WithDefaultValue(false),
	)

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		ClientIdField,
		ClientSecretField,
		RegionField,
		BaseURLField,
		IngestPasswordRiskField,
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("CrowdStrike"),
	field.WithHelpUrl("/docs/baton/crowdstrike"),
	field.WithIconUrl("/static/app-icons/crowdstrike.svg"),
)
