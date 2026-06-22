# test-server

An in-process mock of the CrowdStrike Falcon user-management API. It is a
**developer aid** to exercise and understand the `baton-crowdstrike` account
provisioning lifecycle (create / update / delete users, grant / revoke roles)
without a real Falcon tenant. It is not part of the connector and is never
shipped with it.

## How it trusts work without connector changes

The gofalcon SDK hardcodes HTTPS for both the OAuth token request and all API
calls, so the server speaks TLS with a self-signed certificate. Rather than
adding any test-only flag to the connector, the server writes its certificate to
disk and you point Go's standard `SSL_CERT_FILE` environment variable at it — the
connector then trusts the mock with **zero code changes**.

## Run

```bash
# Terminal 1 — start the mock API (writes ./test-server-cert.pem)
go run ./test-server                        # listens on https://127.0.0.1:8443

# Terminal 2 — point the connector at it
go build -o baton-crowdstrike ./cmd/baton-crowdstrike

export SSL_CERT_FILE="$PWD/test-server-cert.pem"
CFG="--crowdstrike-client-id test --crowdstrike-client-secret test --base-url 127.0.0.1:8443"

# Full sync (user + role + security_insight all work offline)
./baton-crowdstrike $CFG --file sync.c1z

# Create an account (idempotent: re-running returns AlreadyExists, not an error)
./baton-crowdstrike $CFG -p \
  --create-account-login "carol@example.com" \
  --create-account-profile '{"email":"carol@example.com","first_name":"Carol","last_name":"Carter"}'

# Grant / revoke a role (entitlement is "role:<role_id>:member")
./baton-crowdstrike $CFG -p \
  --grant-entitlement "role:falcon_read_only:member" \
  --grant-principal "<uuid>" --grant-principal-type user
./baton-crowdstrike $CFG -p \
  --revoke-grant "role:falcon_read_only:member:user:<uuid>"

# Update a profile — resource-scoped action (user_id is a ResourceId object)
./baton-crowdstrike $CFG \
  --invoke-action update_profile --invoke-action-resource-type user \
  --invoke-action-args '{"user_id":{"resource_type_id":"user","resource_id":"<uuid>"},"first_name":"Caroline"}'

# Update a profile — global action (used by C1 push rules; user_profile is a JSON string)
./baton-crowdstrike $CFG \
  --invoke-action update_user \
  --invoke-action-args '{"user_id":"<uuid>","user_profile":"{\"first_name\":\"Caroline\"}"}'

# Delete an account (idempotent: deleting an already-deleted user succeeds)
./baton-crowdstrike $CFG -p \
  --delete-resource "<uuid>" --delete-resource-type user
```

## Flags

| Flag         | Default                | Description                                 |
| :----------- | :--------------------- | :------------------------------------------ |
| `--addr`     | `127.0.0.1:8443`       | Address to listen on.                       |
| `--cert-out` | `test-server-cert.pem` | Where to write the self-signed certificate. |

## Seed data

- Roles: `falcon_administrator`, `falcon_analyst`, `falcon_read_only`
- Users: `alice@example.com` (admin), `bob@example.com` (analyst + read-only)

## Using with Postman

There is a single Postman collection for the connector in
[`../docs/API/`](../docs/API/); it is shared with the real Falcon API. To point
it at this mock instead of a real tenant, override these environment variables:

| Variable       | Mock value                             |
| :------------- | :------------------------------------- |
| `baseUrl`      | `https://127.0.0.1:8443`               |
| `clientId`     | `test`                                 |
| `clientSecret` | `test`                                 |
| `userUuid`     | `11111111-1111-1111-1111-111111111111` |
| `cid`          | `abcdef1234567890abcdef1234567890`     |
| `roleId`       | `falcon_read_only`                     |

Run **Auth > Get OAuth Token** first — it stores the bearer token in
`{{accessToken}}` for every other request. Because the server uses a self-signed
certificate, turn **SSL certificate verification** off in Postman
(Settings > General).

Per-endpoint upstream API doc links live in
[`../docs/docs-info.md`](../docs/docs-info.md) ("API Endpoints Used"), not here,
to keep a single source of truth.

## Note on the `security_insight` resource type

The `security_insight` (Identity Protection) resource type talks to a separate
GraphQL endpoint (`/identity-protection/combined/graphql/v1`). The mock now
covers it too, returning one identity risk node per seeded user, so a **full
sync runs fully offline** — no `--sync-resource-types` filter required.

For the connector to reach the mock's GraphQL endpoint, `--base-url` is honored
by the Identity Protection client (it mirrors gofalcon's `HostOverride`); in
production `--base-url` is unset and the client uses the region host.
