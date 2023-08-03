package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	ClientId     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.ClientId == "" || cfg.ClientSecret == "" {
		return fmt.Errorf("client_id and client_secret must be provided")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("client_id", "", "CrowdStrike client ID used to generate the access token. ($BATON_CLIENT_ID)")
	cmd.PersistentFlags().String("client_secret", "", "CrowdStrike client secret used to generate the access token. ($BATON_CLIENT_SECRET)")
}
