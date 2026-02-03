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
	RegionField = field.StringField(
		"region",
		field.WithDisplayName("Region"),
		field.WithDescription("CrowdStrike region to connect to. Options include 'us-1', 'us-2', 'eu-1', and 'us-gov-1'."),
		field.WithDefaultValue("us-1"),
	)
	EnableSecurityInsightsField = field.BoolField(
		"enable-security-insights",
		field.WithDisplayName("Enable Security Insights"),
		field.WithDescription("Enable syncing of identity risk scores from CrowdStrike Identity Protection. Requires Identity Protection Entities: Read API scope."),
		field.WithDefaultValue(false),
	)

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		ClientIdField,
		ClientSecretField,
		RegionField,
		EnableSecurityInsightsField,
	}
)

//go:generate go run ./gen
var ConfigurationSchema = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("CrowdStrike"),
	field.WithHelpUrl("/docs/baton/crowdstrike"),
	field.WithIconUrl("/static/app-icons/crowdstrike.svg"),
)
