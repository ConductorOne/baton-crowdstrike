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

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		ClientIdField,
		ClientSecretField,
		RegionField,
		BaseURLField,
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("CrowdStrike"),
	field.WithHelpUrl("/docs/baton/crowdstrike"),
	field.WithIconUrl("/static/app-icons/crowdstrike.svg"),
)
