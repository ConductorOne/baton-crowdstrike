package main

import (
	cfg "github.com/conductorone/baton-crowdstrike/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("crowdstrike", cfg.ConfigurationSchema)
}
