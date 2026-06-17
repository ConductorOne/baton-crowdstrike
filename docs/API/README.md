# CrowdStrike Falcon API — baton-crowdstrike

Reference for the real CrowdStrike Falcon endpoints the `baton-crowdstrike` connector calls, plus a Postman collection to exercise them.

- `baton-crowdstrike.postman_collection.json` — requests for every endpoint the connector uses.
- `baton-crowdstrike.postman_environment.json` — variables (base URL + credentials). **Placeholders only — never commit real secrets.**

## Credentials

1. Falcon console → **Support and resources → API clients and keys → Create API client**.
2. Grant scopes, depending on what you need:

   | Scope                        | Access | Needed for                                                                                     |
   | ---------------------------- | ------ | ---------------------------------------------------------------------------------------------- |
   | User Management              | Read   | Sync `user`, `role` and their grants                                                           |
   | User Management              | Write  | Provisioning: create/delete users, grant/revoke roles, update profile                          |
   | Identity Protection Entities | Read   | Only if syncing `security_insight`                                                             |
   | Identity Protection GraphQL  | Write  | Only if syncing `security_insight` (CrowdStrike requires **Write** even to _read_ risk scores) |

3. Copy `client_id` / `client_secret` into the Postman environment (`clientId` / `clientSecret`), or pass them to the connector via `BATON_CROWDSTRIKE_CLIENT_ID` / `BATON_CROWDSTRIKE_CLIENT_SECRET`.

## Base URL (per cloud / region)

| Cloud    | Base URL                                 |
| -------- | ---------------------------------------- |
| US-1     | `https://api.crowdstrike.com`            |
| US-2     | `https://api.us-2.crowdstrike.com`       |
| EU-1     | `https://api.eu-1.crowdstrike.com`       |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

## Authentication

`POST /oauth2/token` with `grant_type=client_credentials` (form-encoded `client_id` + `client_secret`). Returns **HTTP 201** with `access_token` (bearer, ~30 min). Send it as `Authorization: Bearer <token>` on every other request.

## Selecting what to sync

The connector exposes three resource types. `security_insight` is **opt-in** (disabled by default) and is the only one that needs the Identity Protection scopes.

| Resource type        | Sync ID            | Required scope                                      |
| -------------------- | ------------------ | --------------------------------------------------- |
| Users                | `user`             | User Management: Read                               |
| Roles (+ grants)     | `role`             | User Management: Read                               |
| Identity risk scores | `security_insight` | Identity Protection Entities: Read + GraphQL: Write |

By default a sync includes every enabled resource type. To sync only a subset (e.g. when the API client does **not** have the Identity Protection scopes), pass `--sync-resource-types`:

```bash
# Users + roles only — no Identity Protection scopes needed
./baton-crowdstrike --crowdstrike-client-id=... --crowdstrike-client-secret=... --region=us-2 \
  --sync-resource-types user,role

# Full sync (requires the Identity Protection scopes too)
./baton-crowdstrike --crowdstrike-client-id=... --crowdstrike-client-secret=... --region=us-2
```

If you run a full sync without the Identity Protection scopes, the `security_insight` phase fails with `403 access denied, scope not permitted`. Either add the scopes or restrict the sync with `--sync-resource-types user,role`.

## Endpoints used by the connector

| Operation             | Method | Path                                      | Scope     | Connector use                                              |
| --------------------- | ------ | ----------------------------------------- | --------- | ---------------------------------------------------------- |
| `queryUserV1`         | GET    | `/user-management/queries/users/v1`       | UM: Read  | List user UUIDs (offset pagination) + `uid:'…'` FQL lookup |
| `RetrieveUsersGETV1`  | POST   | `/user-management/entities/users/GET/v1`  | UM: Read  | Full user details by UUID                                  |
| `createUserV1`        | POST   | `/user-management/entities/users/v1`      | UM: Write | Create account (409 = already exists)                      |
| `updateUserV1`        | PATCH  | `/user-management/entities/users/v1`      | UM: Write | Update first/last name (404 = not found)                   |
| `deleteUserV1`        | DELETE | `/user-management/entities/users/v1`      | UM: Write | Delete account (404 = already gone → success)              |
| `queriesRolesV1`      | GET    | `/user-management/queries/roles/v1`       | UM: Read  | List role IDs                                              |
| `entitiesRolesV1`     | GET    | `/user-management/entities/roles/v1`      | UM: Read  | Role details                                               |
| `combinedUserRolesV1` | GET    | `/user-management/combined/user-roles/v1` | UM: Read  | Build grants (roles per user)                              |
| `GrantUserRoleIds`    | POST   | `/user-roles/entities/user-roles/v1`      | UM: Write | Grant role to user                                         |
| `RevokeUserRoleIds`   | DELETE | `/user-roles/entities/user-roles/v1`      | UM: Write | Revoke role from user                                      |

Full API reference: https://developer.crowdstrike.com/api-reference/collections/user-management/

## Notes

- `createUserV1` requires `uid` (email) on a **domain allowlisted** for the tenant; omit `password` to send an activation email.
- Error bodies use `{"errors":[{"code":<status>,"message":"…"}]}`. For status codes not in the OpenAPI spec (e.g. 404/409 on delete/create) gofalcon surfaces a generic `*runtime.APIError` carrying the HTTP status — which is how the connector detects idempotent cases.
