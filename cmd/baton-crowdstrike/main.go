package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-crowdstrike/pkg/connector"
	configSchema "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	version       = "dev"
	connectorName = "baton-crowdstrike"
)

var (
	clientId = field.StringField(
		connector.ClientId,
		field.WithRequired(true),
		field.WithDescription("CrowdStrike client ID used to generate the access token."),
	)
	clientSecret = field.StringField(
		connector.ClientSecret,
		field.WithRequired(true),
		field.WithDescription("CrowdStrike client secret used to generate the access token."),
	)
	region = field.StringField(
		connector.Region,
		field.WithRequired(true),
		field.WithDefaultValue("us-1"),
		field.WithDescription("CrowdStrike region to connect to. Options include 'us-1', 'us-2', 'eu-1', and 'us-gov-1'."),
	)
	configurationFields = []field.SchemaField{clientId, clientSecret, region}
)

func main() {
	ctx := context.Background()
	_, cmd, err := configSchema.DefineConfiguration(ctx,
		connectorName,
		getConnector,
		field.NewConfiguration(configurationFields),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	crowdstrikeConnector, err := connector.New(ctx, cfg)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, crowdstrikeConnector)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
