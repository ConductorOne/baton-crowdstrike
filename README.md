![Baton Logo](./docs/images/baton-logo.png)

# `baton-crowdstrike` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-crowdstrike.svg)](https://pkg.go.dev/github.com/conductorone/baton-crowdstrike) ![main ci](https://github.com/conductorone/baton-crowdstrike/actions/workflows/main.yaml/badge.svg)

`baton-crowdstrike` is a connector for CrowdStrike built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It works with the CrowdStrike Falcon API to sync data about users and their roles.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Prerequisites

Connector requires **client id and secret** to exchange for access token that is later used throughout the communication with API. To obtain these credentials, you have to create API client in CrowdStrike. You must be designated as Falcon administrator role to create API client in CrowdStrike (more info on obtaining access and creating clients [here](https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/)). Administrator will have to provide you with credentials that have access at least to **User management** scope. 

After you have obtained client id and secret, you can use them with connector. You can do this by setting `BATON_CLIENT_ID` and `BATON_CLIENT_SECRET` environment variables or by passing them as flags to `baton-crowdstrike` command.

# Getting Started

Along with credentials, you can also specify region that you want to use. By default, connector will use `us-1` region. You can change this by setting `BATON_REGION` environment variable or by passing `--region` flag to `baton-crowdstrike` command.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-crowdstrike

BATON_CLIENT_ID=client_id BATON_CLIENT_SECRET=client_secret baton-crowdstrike
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_CLIENT_ID=client_id BATON_CLIENT_SECRET=client_secret ghcr.io/conductorone/baton-crowdstrike:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-crowdstrike/cmd/baton-crowdstrike@main

BATON_CLIENT_ID=client_id BATON_CLIENT_SECRET=client_secret baton-crowdstrike
baton resources
```

# Data Model

`baton-crowdstrike` will fetch information about the following CrowdStrike resources:

- Users
- Roles

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-crowdstrike` Command Line Usage

```
baton-crowdstrike

Usage:
  baton-crowdstrike [flags]
  baton-crowdstrike [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string       The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string   The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --client_id string       CrowdStrike client ID used to generate the access token. ($BATON_CLIENT_ID)
      --client_secret string   CrowdStrike client secret used to generate the access token. ($BATON_CLIENT_SECRET)
  -f, --file string            The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                   help for baton-crowdstrike
      --log-format string      The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string       The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --region string          CrowdStrike region to connect to. ($BATON_REGION) (default "us-1")
  -v, --version                version for baton-crowdstrike

Use "baton-crowdstrike [command] --help" for more information about a command.

```
