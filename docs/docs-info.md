# CrowdStrike Connector Setup Guide

---

## Requirements

- A **CrowdStrike Falcon** account
- An **API client** (client ID + client secret) created in the Falcon console
- The **Falcon Administrator** role is required to create an API client

---

## Connector capabilities

1. **What resources does the connector sync?**
   This connector syncs:
   - Users (Falcon console users, identified by uuid; uid is the login/email)
   - Roles (Falcon roles such as `falcon_administrator`, `falcon_analyst`, `falcon_read_only`)
   - Identity Risk Scores (`security_insight`, from Falcon Identity Protection — opt-in, disabled by default)

2. **Can the connector provision any resources? If so, which ones?**
   The connector can provision:
   - Users via `CreateAccount` (`POST /user-management/entities/users/v1`) and `Delete` (`DELETE /user-management/entities/users/v1?user_uuid={uuid}`)
   - Role membership via Grant and Revoke (`POST /user-management/entities/user-role-actions/v1` with `action: grant` / `action: revoke`)
   - A user's first/last name via the `update_user` (global) and `update_profile` (resource-scoped) connector actions (`PATCH /user-management/entities/users/v1?user_uuid={uuid}`)

   > **Note:** Roles and Identity Risk Scores are synced read-only — they are not provisionable. CrowdStrike's REST API has no disable/deactivate flag, so `Delete` is a hard delete and deleting an already-deleted user is treated as success.

---

## Connector credentials

1. **What credentials or information are needed to set up the connector?**
   This connector requires:
   - CrowdStrike API client ID
   - CrowdStrike API client secret
   - CrowdStrike region (defaults to `us-1`)

   **Args**:
   - `--crowdstrike-client-id` — CrowdStrike client ID used to generate the access token (`$BATON_CROWDSTRIKE_CLIENT_ID`)
   - `--crowdstrike-client-secret` — CrowdStrike client secret used to generate the access token (`$BATON_CROWDSTRIKE_CLIENT_SECRET`)
   - `--region` — CrowdStrike region: `us-1`, `us-2`, `eu-1`, or `us-gov-1` (`$BATON_REGION`, default `us-1`)

2. **For each item in the list above:**
   - **How does a user create or look up that credential or info?**

     **API client (client ID + secret):**
     1. Log in to the Falcon console.
     2. Go to **Support and resources** > **API clients and keys**.
     3. Click **Create API client**.
     4. Name the client (e.g. `conductorone-connector`) and select the required API scopes (see below).
     5. Click **Create**. Copy the client ID and secret immediately — the secret is shown only once.

   - **Does the credential need any specific scopes or permissions?**
     CrowdStrike uses an API-scope model (not OAuth scopes). The API client needs:
     - **User Management: Read** — required to sync users and roles.
     - **User Management: Write** — required to provision users and role membership.
     - **Identity Protection Entities: Read** + **Identity Protection GraphQL: Write** — required only for the opt-in `security_insight` resource type.

   - **Is the list of scopes or permissions different to sync (read) versus provision (read-write)?**
     Yes. **User Management: Read** is enough to sync users and roles. **User Management: Write** is additionally required to provision (create/delete users, grant/revoke roles, update profiles).

   - **What level of access or permissions does the user need in order to create the credentials?**
     The user creating the API client must hold the **Falcon Administrator** role.

---

## Resource Details

### Users

- **Resource type ID**: `user`
- **Description**: Falcon console users. `uuid` is the stable resource ID; `uid` is the login/email.
- **Traits**: User trait with email, login, status (active → enabled, inactive → disabled), profile (cid, login, user_id, first_name, last_name), and last login when present.
- **Entitlements**: None (`SkipEntitlements`) — role membership is modeled on the role resource.
- **Grants**: Role memberships the user holds, emitted from the user builder (`GET /user-management/combined/user-roles/v1`).
- **Provisioning**: `CreateAccount` (passwordless; CrowdStrike sends an activation email) and `Delete` (hard delete).
- **Actions**: `update_user` (global) and `update_profile` (resource-scoped) update first/last name.

### Roles

- **Resource type ID**: `role`
- **Description**: Falcon roles. The role ID is the stable resource ID.
- **Traits**: Role trait with profile (role_id, role_name, description).
- **Entitlements**: One `member` assignment entitlement per role, grantable to users.
- **Grants**: Emitted from the user builder (`SkipGrants` on the role itself) to avoid an O(N×M) scan.
- **Provisioning**: Grant assigns a role to a user; Revoke removes it. Both call `POST /user-management/entities/user-role-actions/v1` (the user's CID is resolved from the user record and sent in the request body alongside the UUID and role IDs). The endpoint is idempotent at the API level — re-granting a held role or revoking an absent one returns `200`, so no `409 Conflict` special-casing is needed.

### Identity Risk Scores

- **Resource type ID**: `security_insight`
- **Description**: Identity risk scores from Falcon Identity Protection (risk score 0–1 plus contributing risk factors).
- **Traits**: Security insight trait.
- **Entitlements / Grants**: None (`SkipEntitlementsAndGrants`).
- **Opt-in**: `OptInRequired` — the resource type is disabled by default and must be enabled in ConductorOne. It talks to a separate Identity Protection GraphQL endpoint and requires the Identity Protection scopes.

---

## Authentication

The connector authenticates with the CrowdStrike Falcon API via OAuth2 client credentials, handled by the [gofalcon](https://github.com/crowdstrike/gofalcon) SDK:

1. The connector exchanges the client ID + secret for a bearer access token (`POST /oauth2/token`).
2. The token is sent as a `Bearer` header on every subsequent API call.
3. The region selects the API host (`us-1`, `us-2`, `eu-1`, `us-gov-1`); `--base-url` overrides the host for local testing against the mock test server.

---

## API Endpoints Used

CrowdStrike's official API reference is gated behind the Falcon console (**Support and resources** > **API clients and keys** > **API reference**). The public FalconPy service-collection docs below mirror the same operations.

**Authentication** ([OAuth2](https://www.falconpy.io/Service-Collections/OAuth2.html)):

- `POST /oauth2/token` — Exchange client credentials for a bearer token.

**User Management** ([User Management](https://www.falconpy.io/Service-Collections/User-Management.html)):

- `GET /user-management/queries/users/v1` — List user UUIDs (offset/limit pagination; FQL `uid:'...'` filter for lookups).
- `POST /user-management/entities/users/GET/v1` — Retrieve full user details for a batch of UUIDs.
- `POST /user-management/entities/users/v1` — Create a user (`CreateAccount`).
- `PATCH /user-management/entities/users/v1?user_uuid={uuid}` — Update a user's first/last name (profile actions).
- `DELETE /user-management/entities/users/v1?user_uuid={uuid}` — Delete a user (`Delete`).
- `GET /user-management/queries/roles/v1` — List all role IDs.
- `GET /user-management/entities/roles/v1?ids={id}` — Retrieve role details.
- `GET /user-management/combined/user-roles/v1?user_uuid={uuid}` — List the roles a user holds (user grants).
- `POST /user-management/entities/user-role-actions/v1` — Grant or revoke role membership for a user (request body: `action` = `grant`/`revoke`, `cid`, `uuid`, `role_ids`). Grant and revoke share this single endpoint, in the same `user-management` API family as the read above, which keeps writes and reads consistent.

**Identity Protection** ([Identity Protection](https://www.falconpy.io/Service-Collections/Identity-Protection.html), opt-in):

- `POST /identity-protection/combined/graphql/v1` — Query identity risk scores via GraphQL.

---

## Pagination

- Users (`/user-management/queries/users/v1`): offset/limit pagination; the connector pages UUIDs, then batch-retrieves details.
- User roles (`/user-management/combined/user-roles/v1`): offset/limit pagination.
- Roles (`/user-management/queries/roles/v1`): no pagination — all role IDs are returned in a single response, then details are fetched by IDs.

---

## Rate Limits

- The CrowdStrike API returns `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers; the connector surfaces them as rate-limit annotations.
- Retry/back-off is handled automatically by the SDK.

---

## API Documentation

**Official CrowdStrike references:**

- **API clients and scopes**: Falcon console > **Support and resources** > **API clients and keys** (login required).
- **gofalcon SDK** (used by this connector): https://github.com/crowdstrike/gofalcon
- **FalconPy service collections** (public mirror of the API operations): https://www.falconpy.io/Service-Collections/

**Postman Collection:**

- `docs/API/baton-crowdstrike.postman_collection.json`
- `docs/API/baton-crowdstrike.postman_environment.json`

---

## Test server

A local mock of the Falcon user-management API ships in [`test-server/`](../test-server/README.md). It lets you exercise the full sync and provisioning lifecycle (create/update/delete users, grant/revoke roles) without a real Falcon tenant. See `test-server/README.md` for usage, seed data, and the Postman environment values to run the `docs/API/` collection against the mock.
