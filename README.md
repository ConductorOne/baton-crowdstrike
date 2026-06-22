![Baton Logo](./baton-logo.png)

# `baton-crowdstrike` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-crowdstrike.svg)](https://pkg.go.dev/github.com/conductorone/baton-crowdstrike) ![verify](https://github.com/conductorone/baton-crowdstrike/actions/workflows/verify.yaml/badge.svg)

`baton-crowdstrike` is a connector for CrowdStrike built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It works with the CrowdStrike Falcon API to sync users, roles, and identity risk scores, with provisioning support for account creation/deletion, role membership, and user profile updates.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Prerequisites

The connector requires a **client ID and secret** to exchange for an access token that is used throughout communication with the API. To obtain these credentials, create an API client in CrowdStrike. You must be designated as a **Falcon Administrator** to create an API client (more info on obtaining access and creating clients [here](https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/)).

## Required API Scopes

| Scope                                  | Required          | Description                                          |
| -------------------------------------- | ----------------- | ---------------------------------------------------- |
| **User Management: Read**              | Yes               | Sync users and roles                                 |
| **User Management: Write**             | For provisioning  | Create/delete users, grant/revoke roles, update name |
| **Identity Protection Entities: Read** | For risk scores   | Sync identity risk scores (opt-in `security_insight`)|
| **Identity Protection GraphQL: Write** | For risk scores   | Required by CrowdStrike to fetch risk score data     |

# Getting Started

Along with credentials, you can specify the region to use. By default, the connector uses the `us-1` region. Change this by setting `BATON_REGION` or passing the `--region` flag.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-crowdstrike

BATON_CROWDSTRIKE_CLIENT_ID=client_id BATON_CROWDSTRIKE_CLIENT_SECRET=client_secret baton-crowdstrike
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_CROWDSTRIKE_CLIENT_ID=client_id -e BATON_CROWDSTRIKE_CLIENT_SECRET=client_secret ghcr.io/conductorone/baton-crowdstrike:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-crowdstrike/cmd/baton-crowdstrike@main

BATON_CROWDSTRIKE_CLIENT_ID=client_id BATON_CROWDSTRIKE_CLIENT_SECRET=client_secret baton-crowdstrike
baton resources
```

## Environment variables

```bash
export BATON_CROWDSTRIKE_CLIENT_ID="client_id"
export BATON_CROWDSTRIKE_CLIENT_SECRET="client_secret"
export BATON_REGION="us-1"

baton-crowdstrike
baton resources
```

# Data Model

`baton-crowdstrike` syncs the following resources:

- **Users** (`user`) — Falcon console users; `uuid` is the stable resource ID and `uid` is the login/email
- **Roles** (`role`) — Falcon roles (e.g. `falcon_administrator`, `falcon_analyst`, `falcon_read_only`) with a `member` assignment entitlement
- **Identity Risk Scores** (`security_insight`) — Falcon Identity Protection risk scores (opt-in, disabled by default)

| Resource             | Sync | Provision                                          |
| -------------------- | ---- | -------------------------------------------------- |
| Users                | Yes  | Yes (create / delete, and update first/last name)  |
| Roles                | Yes  | Yes (Grant / Revoke role membership)               |
| Identity Risk Scores | Yes  | No (synced read-only, opt-in)                      |

# Provisioning

Provisioning actions require the `--provisioning` (`-p`) flag and **User Management: Write** scope. Resource IDs (UUIDs) can be found via `baton resources` after a sync.

## Create / delete a user account

```bash
# Create (idempotent: an existing uid/email returns AlreadyExists, not an error)
baton-crowdstrike -p \
  --create-account-login "jane.doe@example.com" \
  --create-account-profile '{"email":"jane.doe@example.com","first_name":"Jane","last_name":"Doe"}'

# Delete (hard delete; deleting an already-deleted user succeeds)
baton-crowdstrike -p \
  --delete-resource "<user-uuid>" --delete-resource-type user
```

## Grant / revoke role membership

```bash
baton-crowdstrike -p \
  --grant-entitlement "role:falcon_read_only:member" \
  --grant-principal "<user-uuid>" --grant-principal-type user

baton-crowdstrike -p \
  --revoke-grant "role:falcon_read_only:member:user:<user-uuid>"
```

## Update a user's first/last name

The connector exposes two profile-update actions: `update_profile` (resource-scoped, `user_id` is a ResourceId) and `update_user` (global, used by C1 push rules, with a `user_profile` JSON string). Omitted name fields are preserved.

```bash
# Resource-scoped action
baton-crowdstrike \
  --invoke-action update_profile --invoke-action-resource-type user \
  --invoke-action-args '{"user_id":{"resource_type_id":"user","resource_id":"<user-uuid>"},"first_name":"Caroline"}'

# Global action
baton-crowdstrike \
  --invoke-action update_user \
  --invoke-action-args '{"user_id":{"resource_type_id":"user","resource_id":"<user-uuid>"},"user_profile":"{\"first_name\":\"Caroline\"}"}'
```

> **Note:** CrowdStrike's REST API has no disable/deactivate flag on the user object. When C1 deprovisions a user it revokes all of the user's role grants (soft deprovisioning); hard deletion of the account is permanent and only happens when an explicit delete is requested.

# Local development

A mock of the CrowdStrike Falcon user-management API ships in [`test-server/`](./test-server/README.md). It lets you exercise the full sync and provisioning lifecycle without a real Falcon tenant:

```bash
# Terminal 1 — start the mock (writes ./test-server-cert.pem)
go run ./test-server

# Terminal 2 — point the connector at the mock
go build -o baton-crowdstrike ./cmd/baton-crowdstrike
export SSL_CERT_FILE="$PWD/test-server-cert.pem"
./baton-crowdstrike --crowdstrike-client-id test --crowdstrike-client-secret test \
  --base-url 127.0.0.1:8443 --sync-resource-types user,role
```

See [`test-server/README.md`](./test-server/README.md) for seed data and all lifecycle commands, and [`docs/API/`](./docs/API) for the Postman collection (it works against both the real Falcon API and the local mock — see the test-server README for the mock override values).

# Documentation

- [`docs/docs-info.md`](./docs/docs-info.md) — Setup guide: capabilities, credentials, resource reference, and API endpoint links
- [`docs/connector.mdx`](./docs/connector.mdx) — Customer-facing setup documentation
- [`test-server/README.md`](./test-server/README.md) — Mock API usage, seed data, and Postman collection

# Security Insights

The connector can sync identity risk scores from CrowdStrike Identity Protection. This includes:

- **Risk Score**: A numerical score (0-1) indicating the identity's risk level
- **Risk Factors**: The factors contributing to the risk score (e.g. "WEAK_PASSWORD (HIGH)", "MFA_NOT_ENABLED (MEDIUM)")

To sync security insights, your CrowdStrike API client must have the **Identity Protection Entities: Read** and **Identity Protection GraphQL: Write** scopes enabled. The `security_insight` resource type is disabled by default and can be enabled through ConductorOne.

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
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --crowdstrike-client-id string       required: The CrowdStrike client ID used to generate the access token. ($BATON_CROWDSTRIKE_CLIENT_ID)
      --crowdstrike-client-secret string   required: The CrowdStrike client secret used to generate the access token. ($BATON_CROWDSTRIKE_CLIENT_SECRET)
      --region string                      CrowdStrike region to connect to. Options include 'us-1', 'us-2', 'eu-1', and 'us-gov-1'. ($BATON_REGION) (default "us-1")
      --client-id string                   The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string               The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                        The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                               help for baton-crowdstrike
      --log-format string                  The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                   The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                       This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                     This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --sync-resource-types strings        The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --ticketing                          This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                            version for baton-crowdstrike

Use "baton-crowdstrike [command] --help" for more information about a command.
```
