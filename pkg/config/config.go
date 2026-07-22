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
	IngestRiskScoresField = field.BoolField(
		"crowdstrike-ingest-risk-scores",
		field.WithDisplayName("Ingest identity risk scores"),
		field.WithDescription("On by default (early access). Syncs Falcon Identity Protection risk scores and risk factors as "+
			"security insights on identities; requires the Identity Protection scopes. Turn off to disable."),
		field.WithDefaultValue(true),
	)
	DetectShadowMCPField = field.BoolField(
		"crowdstrike-detect-shadow-mcp",
		field.WithDisplayName("Detect shadow MCP servers"),
		field.WithDescription("Opt-in. When enabled, scan EDR detections for shadow MCP servers and sync them — with the endpoint "+
			"users that ran them, correlated to identities. Off by default; requires the Alerts read scope."),
		field.WithDefaultValue(false),
	)
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
		IngestRiskScoresField,
		DetectShadowMCPField,
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
