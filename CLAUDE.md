st# Backend — SecOPs API

Part of the SecOPs multi-tenant SOC SaaS platform (SIEM, SOAR, CTI, EDR, DFIR, VM modules).
See root `CLAUDE.md` for overall project context.

# Stack

- NestJS (modular monolith — not microservices)
- PostgreSQL with Prisma

# Architecture decisions

- Shared-database multi-tenancy with `tenant_id` isolation on relevant tables/queries
- Unified `SecurityModule` contract interface that each security module (SIEM, SOAR, CTI,
  EDR, DFIR, VM) implements, for consistency across the platform
- Redis deferred — don't introduce it unless there's a clear need

# Security modules — architecture spec (built — see "Module implementation plan" below)

Source: root `CLAUDE.md`'s "Security modules architecture" section points here for detail.
**Status as of 2026-08-19: all six modules are implemented and live-verified** — every phase
in the "Module implementation plan — SIEM / SOAR / CTI / EDR / DFIR / VM" section below is
checked off, including the asset aggregator (Phase 7) and real-time SSE delivery (Phase 8).
The spec shapes documented in this section (below) describe the design that was actually
built against, kept here as the durable reference for the contract types/DB schema rather
than removed once implemented. `TenantModule` (model) and `ModuleName`/`ModuleSourceType`
(enums) exist in `prisma/schema.prisma` — this is the platform-level "which modules is this
tenant subscribed to" table (matches the spec's `tenant_modules`), not any per-module data
table; the module-specific tables (`siem_*`, `edr_*`, etc.) all exist too, see each phase's
own Prisma models below.

**Six modules + one cross-module aggregator**: SIEM (detection & alerts), SOAR (automation),
CTI (threat intel), EDR (endpoint telemetry), DFIR (incident response), VM (vulnerability
management). `Asset` is not its own module — it's a virtual aggregation view over records
from all six (SIEM Logs, SIEM Alerts, EDR Detections, Vulnerabilities, DFIR Incidents, SOAR
Actions, CTI Observations).

**Unified internal event envelope** — every ingested event/detection/alert, regardless of
source, is normalized into this shape before processing; `data` is the module-specific
payload, the envelope itself never changes shape. This is what lets SOAR/DFIR consume events
from any module without knowing its internals:

```ts
type Severity = 'low' | 'medium' | 'high' | 'critical'
type EventSource = 'edr' | 'siem' | 'cti' | 'vm' | 'api'
type EventType = 'alert' | 'event' | 'detection' | 'ioc' | 'vulnerability'

interface UnifiedEvent {
  tenant_id: string
  timestamp: string   // ISO 8601
  source: EventSource
  type: EventType
  severity: Severity
  data: Record<string, unknown>
}
```

**`SecurityModule` contract** — every module's NestJS service implements this; the
orchestration layer calls `ingest()`/`query()` without knowing the concrete module:

```ts
interface SecurityModule {
  ingest(event: UnifiedEvent): Promise<void>       // receive and store a normalized event
  query(filters: QueryFilters): Promise<any[]>      // return filtered records for this module
  healthCheck(): Promise<ModuleHealth>              // confirm module is operational
}

interface ModuleHealth {
  module: string
  status: 'ok' | 'degraded' | 'down'
  last_ingestion?: string
}
```

**Orchestration is internal, not inter-service.** Each step below is a service method
triggered by an internal NestJS event emitter, not an HTTP call — same process, same
modular-monolith rule as everything else in this repo:

```
EDR agent pushes telemetry (POST /edr/events)
  → EDR service normalizes, saves edr_detection, emits event
  → SIEM ingest receives, saves siem_alert, emits event
  → CTI service checks IOCs, enriches on match (severity may escalate)
  → SOAR service checks triggers, fires playbook, saves soar_execution
  → DFIR service creates incident, links related records
```

Two named example flows from the spec: `EDR → SIEM (alert) → SOAR (playbook) → DFIR
(incident)`, and `EDR/SIEM event → CTI enrichment → enhanced alert stored back in SIEM`.

**Planned DB schema, by module** (all tenant-scoped tables carry `tenant_id`; none of these
exist in `schema.prisma` yet — build them when that module's turn comes up, don't
pre-create all six at once):

- SIEM: `siem_logs` (source, event_type, severity, raw_data, timestamp), `siem_alerts`
  (title, severity, status, created_at)
- EDR: `edr_endpoints` (hostname, ip, os, status, last_seen), `edr_detections`
  (endpoint_id, detection_name, severity)
- CTI: `cti_iocs` (type, value, confidence, source)
- SOAR: `soar_playbooks` (name, trigger_condition, actions), `soar_executions`
  (playbook_id, alert_id, status, logs)
- DFIR: `dfir_incidents` (title, severity, status, created_at), `dfir_links`
  (incident_id, source_type, source_id — polymorphic link to any other module's record)
- VM: `vm_assets` (name, ip, type), `vm_vulnerabilities` (asset_id, severity, description)

**Open input required before starting implementation** (per the spec's design-summary
section): each module's real API documentation, or test/sandbox APIs to integrate against —
and the final third-party dependency list. Don't guess a module's external API shape;
confirm docs/test API exist for that module before building its ingestion path.

# User provisioning & RBAC hierarchy

No public sign-up exists anywhere in this platform. Every user, at every role, is created by
someone above them in the hierarchy — never by themselves.

```
                     ┌───────────────────────────────────────┐
                     │              SUPER ADMIN                │
                     │  seeded once via a seed script —         │
                     │  NEVER exposed as an HTTP route          │
                     │  • not bound to any tenant                │
                     │  • creates Tenants                        │
                     │  • creates each Tenant's first Admin      │
                     └───────────────────┬─────────────────────┘
                                         │ creates
                                         ▼
                     ┌───────────────────────────────────────┐
                     │                 ADMIN                    │
                     │  tenant-scoped                            │
                     │  • full control within their own tenant   │
                     │  • creates co-Admin, Analyst, or Viewer    │
                     │    accounts, scoped to their own tenant_id │
                     │    only (self-loop: Admin → Admin)         │
                     └───────────────────┬─────────────────────┘
                                         │ creates
                         ┌───────────────┴────────────────┐
                         ▼                                 ▼
             ┌─────────────────────┐           ┌─────────────────────┐
             │       ANALYST         │           │       VIEWER          │
             │  tenant-scoped         │           │  tenant-scoped         │
             │  investigate alerts,   │           │  read-only:            │
             │  SIEM/CTI/DFIR work,   │           │  dashboards & alerts   │
             │  can trigger SOAR      │           │                        │
             └─────────────────────┘           └─────────────────────┘
```

Hard rules that follow from this:
- No `/auth/register` or equivalent self-signup endpoint exists, ever.
- A new user's `tenant_id` always comes from the creator's own auth token
  (`request.user.tenantId`), never from the request body — otherwise a compromised Admin
  could create users in a different tenant (cross-tenant privilege escalation).
- A new user's `role` is determined by which endpoint/action is called, never by a
  client-supplied `role` field in the request body.
- An Admin may create another Admin in their own tenant (co-Admin), in addition to
  Analyst/Viewer — same tenant-scoping rule applies (`tenant_id` from the creator's token,
  never the request body). This is the one hierarchy self-loop (Admin → Admin); every other
  role is only ever created by the level above it.
- The very first Super Admin is bootstrapped by a one-time seed script (reads credentials
  from env vars, run directly against the DB) — not by any API call, since no user exists
  yet to authorize creating one.
- An Admin cannot delete their own account (`DELETE /users/:id` where `:id` matches the
  caller's own user ID is rejected), to prevent a tenant from being accidentally locked out
  of Admin access. Deleting another co-Admin in the same tenant is allowed.
- An Admin cannot change their own role via `PATCH /users/:id/role` (same self-target
  rejection), to avoid accidental self-demotion/lockout.
- An Admin cannot reset their own password via `POST /users/:id/reset-password` — that route
  sets an Admin-chosen password with no proof of the old one, so allowing it on yourself would
  let a stolen/leaked bearer token turn into permanent account takeover (attacker resets the
  password without ever knowing it).
- Every new user, at every level — a tenant's first Admin (`TenantsService.
  createTenantWithAdmin`) and any subordinate (`UsersService.createUser`) — is created with
  `mustChangePassword: true`, explicitly set in the create call. This used to rely on the
  Prisma column default (`@default(false)`), which was a real bug: it meant no new account
  was ever actually forced through the change flow (found 2026-07-28 by creating a live
  tenant/Admin through the running API and observing `mustChangePassword: false` on login —
  see `docs/superpowers/specs/2026-07-28-password-change-request-flow-design.md`). Don't
  reintroduce reliance on the column default.
- `PATCH /users/me/password` (current-password-gated self-change) only works while
  `mustChangePassword` is still `true` — it exists solely to complete the mandatory
  first-time change, checked against the fresh DB value in `UsersService.changePassword`
  (not the JWT claim, which can be stale relative to an admin-triggered reset). Once that's
  done, there is no voluntary "change my password whenever I want" path for any role,
  including Admins — a stolen bearer token alone can no longer be turned into a silent
  password change. Voluntary rotation instead goes through:
  - `POST /users/me/request-password-change` — any authenticated, non-forced user (blocked
    by `MustChangePasswordGuard` while still forced, same as any other route). Sets
    `passwordResetRequestedAt` on the caller's own row; doesn't touch the password itself.
  - `GET /users/me/pending-password-requests` (`@Roles(ADMIN, SUPER_ADMIN)`) →
    `{ hasPending: boolean }`. **Single designated recipient per tenant**: the tenant's
    first-created Admin (earliest `createdAt` among `role=ADMIN` in that tenant, computed
    live, not stored — stays correct if that Admin is later deleted) is the only one who
    sees `true` for another tenant member's request; a co-Admin always gets `false` here
    (they can still see the raw per-row status by browsing `(dashboard)/users`, just no
    ambient ping). The first Admin's own request never pings themselves — it escalates to
    **every** Super Admin instead (`hasPendingPasswordRequestsForSuperAdmin`), since a sole/
    first Admin has no one else in-tenant to notify.
- Demoting a tenant's last remaining Admin to a non-Admin role is rejected
  (`ConflictException`) — every tenant must always have at least one Admin.
- `POST /users/:id/reset-password` also accepts a `SUPER_ADMIN` caller now (2026-07-23),
  routed to `UsersService.resetSoleAdminPassword` instead of the tenant-scoped
  `resetPasswordForTenant` — but only when the target is an Admin with no co-Admin in their
  tenant (`ConflictException` otherwise: "This tenant has other Admins who can reset this
  password"). This is the one place a Super Admin acts on an existing Admin rather than just
  creating one — a deliberate, narrow exception to the hierarchy above, added only because a
  tenant with a single, locked-out Admin has no other in-tenant way to recover. Both paths
  converge on the same effect (`mustChangePassword: true`, `passwordResetRequestedAt: null`).
- Login (`POST /auth/login`) always calls `argon2.verify` — even when the email doesn't
  match any user, it verifies against a fixed dummy hash — so response timing can't be used
  to enumerate which emails have accounts (argon2's cost makes the found-vs-not-found timing
  gap large enough to be trivially measurable otherwise; verified empirically at ~78ms).

# Auth: refresh token rotation & logout (added 2026-08-05)

Replaces the earlier "stateless JWT only, no refresh tokens, no sessions" design (still the
description you'll find in older internal docs/notes — this section supersedes it). Driven
by two gaps identified while auditing what the backend still didn't cover once all six
security modules were done: no session revocation (a leaked access token was valid for a
full hour with no way to kill it), and no way for a client to stay logged in beyond that
hour without re-entering credentials.

- `RefreshToken` model: `{ id, userId, tokenHash, familyId, expiresAt, revokedAt,
  replacedByTokenId?, createdAt }`. `tokenHash` is SHA-256 (not argon2) — the raw token is
  already a 32-byte random value from `crypto.randomBytes`, not a human password, so a fast
  hash is enough to protect the DB-at-rest copy without taxing every refresh call.
- Access token lifetime dropped from `1h` to `15m`. This — not a blocklist — is the real
  mitigation for a stolen access token: a stateless JWT can't be revoked before it expires
  without reintroducing shared state, and Redis stays out of scope, so the fix is shrinking
  the window instead. **Gap found and fixed 2026-08-07** (during the frontend's Phase 1 auth
  migration, verifying this file against the actual backend source): `users.module.ts` has
  its own separate `JwtModule` registration — used by `UsersController.changeMyPassword` to
  re-sign a fresh access token right after the mandatory first-login password change — and
  it had been left at `expiresIn: '1h'` when this migration landed on 2026-08-05, so that one
  specific token (the one every newly-created account's first login mints) lived 4x longer
  than every other access token in the system. Now `15m`, matching `auth.module.ts`.
- **Rotation on every use, with reuse detection.** `POST /auth/refresh` revokes the
  presented refresh token and issues a new one in the same `familyId`. If a token that's
  already been revoked is presented again — a stolen-and-replayed token, since the
  legitimate client would only ever hold the latest one — the entire family is revoked,
  not just that one request, forcing a fresh login. Standard OWASP-recommended pattern.
- **Delivery: httpOnly cookie, not the response body.** `access_token` still comes back in
  the JSON body from `/auth/login` and `/auth/refresh` (unchanged shape), but the refresh
  token never does — it's set as a `refresh_token` cookie (`httpOnly`, `SameSite=Lax`,
  `Path=/api/auth` so the browser only attaches it to auth routes). This requires
  `app.enableCors({ origin: process.env.FRONTEND_URL, credentials: true })` in `main.ts`
  (a wildcard CORS origin is incompatible with `credentials: true`) and `cookie-parser`
  wired via `app.use(cookieParser())` — every e2e spec that exercises these routes has to
  replicate that same `app.use(cookieParser())` call in its own test bootstrap, since e2e
  tests build their `INestApplication` directly from `AppModule` rather than calling the
  real `main.ts`. `SameSite=Lax` assumes the frontend reaches this API same-site (e.g. via
  a Next.js BFF proxy, per root `CLAUDE.md`'s SSE note on that same topology question) —
  revisit to `SameSite=None` + HTTPS if the frontend ends up calling this API cross-site
  directly instead.
- `POST /auth/logout` revokes only the presented session's refresh token — **logout kills
  just that session, not every session for the user** (a deliberate choice: no "log out
  everywhere" endpoint exists). It's `@SkipPasswordCheck()`'d so an account stuck in the
  mandatory first-login password-change flow can still log out, but still requires a valid
  (possibly soon-to-expire) access token like any other authenticated route — there's no
  `@Public()` on it.
- Scheduled daily cleanup (`AuthService.cleanupExpiredRefreshTokens`, `@Cron
  (EVERY_DAY_AT_MIDNIGHT)`, reusing the `@nestjs/schedule` wiring Phase 9's polling skeleton
  already set up) deletes only rows past their own `expiresAt` — a revoked-but-not-yet-
  expired row is deliberately left alone, since it's what lets a later `refresh()` call
  detect replay and kill the family; deleting it early would silently drop that
  defense-in-depth.
- Verified three ways: full unit + e2e suites (331 unit / 133 e2e passing, including a
  dedicated `test/auth.e2e-spec.ts` covering rotate → replay-rejected → family-killed and
  logout → cookie-cleared → refresh-rejected), and live against the real dev server +
  Postgres with a real seeded Admin account — confirmed the cookie's actual `Set-Cookie`
  attributes, the family-kill behavior on replay, and that logout without a valid access
  token is rejected.
- **Deliberately not built here**: a "logout everywhere" endpoint (see above). Related but
  separate gap — machine-to-machine auth (API keys) for the ingestion routes — is tracked at
  decision 7 in the module implementation plan below, not here.

# Auth: account lockout & password reuse prevention (added 2026-08-05)

Closes the last real, buildable-now backend gap identified in a completeness review (real
vendor integration and the ingestion API-key work are excluded from that review — both are
blocked on external access that doesn't exist yet, not backend effort).

- **Lockout uses plain counter fields on `User`** (`failedLoginAttempts Int @default(0)`,
  `lockedUntil DateTime?`), not a dedicated table — unlike `RefreshToken`/`PasswordHistory`,
  this is current state, not a history that needs replaying or reuse-detection.
- **5 consecutive failed attempts locks the account for 15 minutes**, reset by any
  successful login. Attempts made *during* an active lockout — whether the password is
  right or wrong — don't extend `lockedUntil` further, bounding the lockout to a fixed
  window no matter how much it's hammered (an unbounded-extension design would let anyone
  who knows a valid email keep that account locked out indefinitely). One real consequence
  worth knowing: since only a *successful* login resets the counter (not the passage of
  time), the very next failure after a lock naturally expires re-locks the account
  immediately — the counter doesn't quietly reset itself just because the timer ran out. If
  that turns out to be too strict in practice, the fix is treating a naturally-expired lock
  as a fresh count starting at 1 rather than incrementing the stale 5.
- **Locked-account responses are identical to a wrong password** — same message, same
  `argon2.verify` call still run unconditionally beforehand. This follows the same
  no-enumeration principle behind the dummy-hash timing fix already in this file: a distinct
  "account locked" response would leak that the email exists and reopen a timing
  side-channel. Trade-off: a legitimately-locked-out user gets no explicit signal that
  they're locked, just the same generic rejection every time.
  Live-verified against the real dev server: 5 real wrong-password requests against a
  seeded Admin set `failedLoginAttempts: 5` and a future `lockedUntil` in Postgres; the
  correct password was then rejected with the identical `"Invalid credentials"` body while
  still locked; fast-forwarding `lockedUntil` into the past (simulating the window elapsing)
  let the same correct password succeed and reset both fields to `0`/`null`.
- **`PasswordHistory` is a dedicated, append-only table** (`userId, hashedPassword,
  createdAt`) — never pruned, since a permanent record of when an account's password
  changed is cheap and useful for later investigation. Only the reuse *check* is bounded: a
  new password is checked via `argon2.verify` (not equality — salts are random) against the
  current hash plus the 4 most recent history rows, i.e. "can't reuse your last 5
  passwords." Applies to both places a password gets set on an existing account —
  `UsersService.changePassword` (self, forced-change) and `resetPasswordForTenant`/
  `resetSoleAdminPassword` (Admin/Super Admin resetting someone else) — via a shared
  `applyPasswordReset` choke point. Does *not* apply to `createUser`/`createTenantWithAdmin`,
  since a brand-new account has no prior password to reuse.
  Live-verified: resetting a seeded Analyst's password, then immediately resetting it again
  to the exact same value, returned `409 New password must not match your current or last 5
  passwords`; resetting to a genuinely different value succeeded, and both changes left a
  row in `PasswordHistory`.
- **An Admin/Super Admin resetting a password also clears any existing lockout**
  (`failedLoginAttempts: 0, lockedUntil: null`) in the same `applyPasswordReset` write —
  otherwise a locked-out account that was just fixed by an Admin would stay artificially
  locked for whatever remained of the 15-minute window.
- Verified three ways: full unit + e2e suites (340 unit / 137 e2e passing, including new
  lockout and reuse-rejection cases in `test/auth.e2e-spec.ts` and `test/users.e2e-spec.ts`),
  and live against the real dev server + Postgres as described above.

# Modules: assign / escalate / resolve workflow (added 2026-08-06)

Not applied uniformly to all six modules — a deliberate, discussed scope decision, not an
oversight. SIEM, EDR, and DFIR are genuine investigation objects (alerts/detections/incidents
that an analyst is assigned to, works, and closes out) and got the full workflow. CTI (`CtiIoc`)
is reference/threat-intel data, not an incident — it gets looked up and matched, never
"resolved" — so it was deliberately left alone. SOAR (`SoarExecution`) is an automated action
log, already terminal (PENDING/RUNNING/SUCCESS/FAILED) by the time a human looks at it — nothing
to assign. VM (`VmVulnerability`) got only `assignedToUserId`, kept orthogonal to its existing
remediation lifecycle (OPEN/REMEDIATED/ACCEPTED_RISK) rather than forced into the same
OPEN/ASSIGNED/ESCALATED/RESOLVED shape as the other three — "who's working this" and "what's the
remediation outcome" are different questions for a vulnerability, and assigning someone doesn't
by itself move the remediation needle.

- **Shared RBAC logic, not tripled**: `src/common/assignment.ts` — `resolveAssignee(prisma,
  caller, tenantId, requestedAssigneeId)` (Admin can assign to any Analyst/Admin in their own
  tenant, verified against the DB; an Analyst can only self-assign, rejected with
  `ForbiddenException` otherwise) and `assertCanTransitionStatus(caller, assignedToUserId)`
  (only the current assignee or an Admin may escalate/resolve). Reused by SIEM/EDR/DFIR/VM's
  services — same reasoning as the `requireTenantId` extraction.
- **One loose endpoint split into two purpose-built actions, everywhere it's built.** This
  closed a real, pre-existing gap in SIEM specifically: its original single `PATCH
  /siem/alerts/:id` accepted both `status` and `assignedToUserId` in one body with no rules at
  all — any Analyst/Admin could set an arbitrary assignee or jump an alert straight from OPEN to
  RESOLVED without it ever being assigned. Now: `POST .../:id/assign` (sets the assignee, moves
  status to ASSIGNED/INVESTIGATING) and `PATCH .../:id/status` (ESCALATED/RESOLVED/CONTAINED
  only — OPEN and the "assigned" state are never directly settable through it), gated by the
  shared RBAC helpers above and a per-module "must currently be assigned" state check.
- **DFIR's status enum grew from 4 to 5 values** (`OPEN, INVESTIGATING, ESCALATED, CONTAINED,
  RESOLVED` — added `ESCALATED`) rather than being collapsed onto SIEM/EDR's plain
  OPEN/ASSIGNED/ESCALATED/RESOLVED shape, since DFIR's richer incident-response semantics
  (INVESTIGATING, CONTAINED) predate this feature and are worth keeping. Assign moves
  OPEN→INVESTIGATING; the tightened status route accepts ESCALATED, CONTAINED, or RESOLVED, all
  gated the same way as SIEM/EDR.
- **`description String?` and `mitreTechniques String[]` added to `SiemAlert`, `EdrDetection`,
  and `DfirIncident`** — the two fields that turn a bare title into something that reads like a
  real incident (this is what the original screenshot comparison was asking for). Native Postgres
  string array for `mitreTechniques`, no join table — sufficient for the current scale.
- **Seed script enriched to match** (`prisma/seed-modules.ts`): every SIEM alert title, EDR
  detection name, and DFIR incident title now has a matched narrative `describe()` template
  referencing the specific seeded host/IP it fired against, plus a plausible MITRE ATT&CK
  technique list — not `faker.hacker.*` gibberish. ~50% of records across all four modules are
  seeded pre-assigned (with a consistent status — e.g. never `RESOLVED` while `assignedToUserId`
  is `null`, which the old purely-random status picker could previously produce, an inconsistent
  state the new business rules would now reject via the API). Verified for real against the dev
  DB, not just "it ran": queried freshly-seeded rows directly and confirmed populated
  `description`/`mitreTechniques`; a `null`-description row found during a naive first check
  turned out to be stale data from an earlier, pre-this-feature seed run in the same dev
  database, confirmed by counting `SiemAlert` rows with a non-null description (225 — exactly 5
  tenants × 45 alerts/tenant from this run) against the total (480, the rest pre-dating the
  columns).
- **Deliberately not built here, tracked as a follow-up**: the investigation-timeline and
  persisted response-task-checklist pieces from the original screenshot comparison. DFIR already
  has an equivalent (`DfirLink` + `getIncidentDetail`); SIEM/EDR don't, and building a real
  timeline sub-model plus a persisted, individually-assignable task checklist is a materially
  bigger lift than the columns above — explicitly deferred, not forgotten.
- Verified three ways: full unit + e2e suites (384 unit / 150 e2e passing, including new
  `src/common/assignment.spec.ts` plus assign/status test blocks across all four modules' unit
  and e2e specs), and live against the real dev server + Postgres — walked the full SIEM chain
  (self-assign → a non-assignee Analyst correctly blocked with 403 → the assignee escalates →
  an Admin resolves), confirmed EDR/DFIR/VM's assign routes independently, and confirmed VM's
  assignment genuinely doesn't touch its remediation `status` field.

## Follow-up: assign/status changes are now observable, not just correct (2026-08-06)

Found during a deliberate "is the backend actually done" pass, not during the original build:
the assign/escalate/resolve actions above wrote the correct data, but nothing else in the system
could see the change happen. `EventsService`'s SSE stream only ever subscribed to `*.created`
events, and the materialized `AssetFeedEntry` table had no `status`/`assignedToUserId` columns at
all — a record could be assigned and resolved and both the live stream and the unified feed would
keep showing it exactly as it looked the moment it was created. This was true of the *existing*
CTI-severity-escalation path too (never fixed until now), not just the new workflow.

- Every assign method (`assignAlert`, `assignDetection`, `assignIncident`, `assignVulnerability`)
  now emits `<module>.<record>.assigned`; every status-transition method
  (`updateAlertStatus`/`updateDetectionStatus`/`updateStatus`) emits
  `<module>.<record>.status_changed`. VM only gets the former, consistent with the original
  scope decision (no status-transition action was built for VM). Shared payload shapes
  (`RecordAssignedPayload`/`RecordStatusChangedPayload`) live in
  `src/common/security-module/types.ts`.
- `AssetFeedEntry` gained `status String?` and `assignedToUserId String? @db.Uuid`. The six
  `*.created` listeners in `AssetService` now stamp `status: 'OPEN', assignedToUserId: null` at
  creation (CTI and SOAR excluded — neither has an assignable status, matching the original
  workflow-scope decision); seven new listeners (`applyAssignment`/`applyStatusChange`, one
  `@OnEvent` per event name since the decorator needs a literal string) update the matching row
  by `tenantId + source + sourceId` in place — this is a materialized view being kept in sync,
  not an audit log, so updating beats appending.
- `EventsService` subscribes to the 7 new event names alongside the existing 6, no other changes
  to its filtering/mapping logic.
- Verified live, in one shot, not just via automated tests: opened a real SSE connection with
  `curl`, then in the same tenant posted an EDR event and walked it through the full chain,
  self-assigned the resulting SIEM alert, then resolved it — the connected client received the
  `siem.alert.assigned` and `siem.alert.status_changed` frames in real time, correctly shaped,
  immediately after the existing `*.created` frames. Separately confirmed against Postgres
  directly that the corresponding `AssetFeedEntry` row's `status`/`assignedToUserId` matched the
  final state. (Two earlier live-capture attempts came back empty — a tooling artifact from
  splitting the SSE listener and the trigger calls across separate shell invocations, which
  killed the backgrounded `curl` before it could receive anything; not a code defect, resolved
  by keeping listener + trigger in one shell session.)
- New test: `test/asset.e2e-spec.ts` — a real HTTP assign then a real HTTP status-change against
  a live `SiemService`, asserting `GET /assets/feed`'s entry updates after each step, including
  that resolving doesn't clobber the `assignedToUserId` set by the earlier assign. 391 unit / 151
  e2e passing.

## Follow-up: "assigned to me" filter + unassign action (2026-08-06)

Found the same way as the two follow-ups above it — not while building the workflow, but while
deliberately re-asking "can someone actually use this" afterward. Two concrete gaps: no query
endpoint (module-level or the unified feed) could filter by `assignedToUserId`, so an Analyst had
no way to ask the API for just their own open work; and once assigned, a record could only be
*re*assigned to someone else, never unassigned back to nobody.

- **Filter**: `assignedToUserId?: string` added to `BaseQueryFilters`/`BaseQueryDto` (shared, so
  every module's query DTO picks it up automatically), wired into SIEM/EDR/DFIR/VM's `query()`
  where-clauses and `AssetService.getUnifiedFeed`. CTI/SOAR's DTOs also accept the field (it's
  shared) but their services simply never reference it, since neither model has that column.
- **Unassign**: `DELETE .../:id/assign` on all four modules (mirrors the existing `POST
  .../:id/assign`), reusing `assertCanTransitionStatus` for RBAC (only the current assignee or
  an Admin) and, for SIEM/EDR/DFIR, the same `TRANSITIONABLE_STATUSES` gate the status-transition
  endpoint already uses — a record can only be unassigned while it's ASSIGNED/INVESTIGATING or
  ESCALATED, not before it was ever assigned or after it's already RESOLVED/CONTAINED. Unassigning
  reverts status to OPEN (SIEM/EDR/DFIR); VM just clears `assignedToUserId`, consistent with
  assignment never touching VM's own remediation status in the first place. Emits
  `<module>.<record>.unassigned` (reusing the `RecordStatusChangedPayload` shape — no new type
  needed), consumed by both `EventsService`'s SSE stream and a new `AssetService.applyUnassignment`
  listener that clears the feed row's `assignedToUserId` alongside its `status`.
- **One real nuance found live, not glossed over**: a non-Admin Analyst who unassigns something
  and then immediately retries gets a `403 Forbidden` ("Only the assigned analyst or an Admin can
  change this status"), not the `409 Conflict` ("must be currently assigned") the state-machine
  check is meant to produce — because `assertCanTransitionStatus` runs first and already rejects
  a non-assignee before the state check is ever reached, since after unassigning nobody is the
  assignee anymore. The end result (the double-unassign is still correctly blocked) is right
  either way; only the *error message* a non-Admin sees in that specific retry case is less
  precise than it could be. Confirmed via a real Admin retry on the same record that the intended
  409 path does fire correctly when an Admin is the one calling it. Left as-is — correct behavior,
  imprecise message in one edge case, not worth a special-cased fix for the message alone.
- Verified three ways: full unit + e2e suites (427 unit / 159 e2e passing, including new
  `unassignAlert`/`unassignDetection`/`unassignIncident`/`unassignVulnerability` describe blocks
  across all four modules' service, controller, and e2e specs, plus `assignedToUserId` filter
  tests on all four `query()` methods and `getUnifiedFeed`), and live against the real dev
  server + Postgres — confirmed the filter empty-before/present-after an assignment on both a
  module endpoint and the unified feed, confirmed unassign reverts SIEM's status to OPEN and
  clears the assignee, confirmed the double-unassign rejection (and the message nuance above),
  and spot-checked DFIR's assign→INVESTIGATING→unassign→OPEN round trip live.

# CTI/SOAR mutability gaps closed + dead-code removal (2026-08-06)

Found the same way as the assign/unassign follow-ups above — a deliberate "what's still
missing" pass over the whole backend rather than a repeat of an earlier answer. Three
unrelated, independently-verified fixes, not a single feature:

**1. CTI IOCs and SOAR playbooks were create-only.** Neither model had any update or delete
route anywhere — confirmed by grep across both services/controllers before writing any code.
A false-positive IOC or a misconfigured playbook had no API-level fix or removal path, ever.
- `PATCH /cti/iocs/:id` / `DELETE /cti/iocs/:id` (Analyst/Admin, matching `POST`'s RBAC).
  `type`/`value` aren't editable — together they're the IOC's identity (the
  `tenantId_type_value` unique key `ingest()` upserts on); only `confidence`/`source` can
  change. Delete emits `cti.ioc.deleted` (`RecordDeletedPayload`, a new type — no existing
  payload shape fit a record that no longer exists to have a status), consumed by both
  `EventsService`'s SSE stream and a new `AssetService.handleCtiIocDeleted` listener that
  `deleteMany`s the matching `AssetFeedEntry` row — the one deliberate exception to every
  other module's "records are never deleted, only status/assignee changes" pattern, since
  CTI IOCs are the one record kind this pass actually made truly deletable.
- `SoarPlaybook` gained `isActive Boolean @default(true)`. `PATCH /soar/playbooks/:id` (Admin)
  edits name/triggerCondition/actions/isActive; `evaluateTriggers`'s `where` clause now filters
  `isActive: true`, so a deactivated playbook stops firing without needing to be deleted.
  `DELETE /soar/playbooks/:id` (Admin) hard-deletes — but only once it's confirmed to have zero
  `SoarExecution` rows (`soarExecution.count({ where: { playbookId } })` up front), otherwise
  `409 Conflict` pointing at the `isActive` toggle instead. **This was originally written as a
  try/delete-and-catch-the-FK-violation instead of a pre-check, guessing the thrown error would
  be a `Prisma.PrismaClientKnownRequestError` with code `P2003`/`P2014` — wrong, confirmed live
  against the real dev DB.** Under this project's Prisma 7 driver-adapter setup
  (`@prisma/adapter-pg`, see `docs/internship-report-backend.md` §4.1/§4.11), a RESTRICT
  violation on `delete()` surfaces as a raw `DriverAdapterError` (`cause.kind ===
  'ForeignKeyConstraintViolation'`, a Postgres-level error from the adapter), not the
  higher-level Prisma client error code the non-adapter query engine produces — the try/catch
  version returned a bare `500` instead of the intended `409` the first time it was actually
  exercised against a playbook with a real execution. Rewritten to the explicit count-check
  instead, which sidesteps the whole question of what shape the underlying error takes.
- **A second, related gap closed in the same pass**: `CreateSoarPlaybookDto.triggerCondition`
  was validated as `@IsObject()` — any shape accepted. `evaluateTriggers` only ever matches on
  a literal `severity` key; anything else silently fails every check in its `.every()` loop, so
  a typo'd key (`severty` instead of `severity`) produced a playbook that could never fire, with
  no error and no way to tell afterward (compounded by there being no delete/update route at the
  time this was found). Replaced with a `TriggerConditionDto` (`@IsEnum(Severity) severity`),
  so the shape is rejected at creation time instead. `actions` deliberately stays a generic
  object — SOAR execution is fully simulated (module-plan decision 8), so there's no real
  schema to validate it against.

**2. Removed the default NestJS scaffold that was still live.** `src/app.controller.ts` /
`src/app.service.ts` (`GET /api` → `"Hello World!"`) and their `test/app.e2e-spec.ts` were the
literal `nest new` boilerplate, never removed, still wired into `app.module.ts`. Deleting the
controller/service was clean — but `test/app.e2e-spec.ts` turned out to be load-bearing: past
the boilerplate route (used only as a convenient "protected, no `@Roles()`" target), it was the
*only* e2e coverage anywhere for `POST /auth/forgot-password`, helmet response headers, and
login rate-limiting (`429` after 5 attempts/minute). Deleting it outright would have silently
dropped that coverage while the suite kept passing — caught before it shipped, not after.
Recreated as `test/security-hardening.e2e-spec.ts` with the same tests, minus the one assertion
tied to the removed route (re-targeted at `GET /api/users/me`, an existing route with no
`@Roles()` restriction). 168 e2e tests, same total as before the rename (11 tests moved, none
lost).

**3. A fourth, unrelated bug found and reported, not fixed.** While live-testing #1 and #2,
cleaning up the test tenant hit the exact same class of bug already fixed once in Phase 8 above
(`deleteTenantWithUsers` missing tables in its dependency-ordered delete) — except for two
tables added *after* that fix, on the same day, and never retrofitted: `RefreshToken` and
`PasswordHistory`. See that section's note for the full detail; not addressed here since it's
unrelated to this pass's actual scope.

- Verified three ways: full unit + e2e suites (447 unit / 168 e2e passing, including new
  `updateIoc`/`deleteIoc`/`updatePlaybook`/`deletePlaybook` describe blocks across both modules'
  service/controller specs, the `TriggerConditionDto` rejection case, and the
  `AssetService.handleCtiIocDeleted` listener test), typecheck and lint clean, and live against
  the real dev server + Postgres — including a real Prisma-client-regeneration gotcha caught
  along the way: `npx prisma migrate dev` had applied the `isActive` migration SQL but the
  generated client wasn't actually carrying the new field until a manual `npx prisma generate`
  (the running dev server's stale client threw `Unknown argument isActive` on the first live
  `PATCH` attempt) — worth checking first if a freshly-migrated field ever 500s as "unknown
  argument" again.

# User deletion: the same RESTRICT-FK bug, a third time (2026-08-06)

Found the same way as the §4.20/§4.21-class findings above — a deliberate "what's still missing"
pass, not a repeat of an earlier answer. `UsersService.removeUserForTenant` (`DELETE
/users/:id`) did a bare `prisma.user.delete()`, with no handling of the exact same class of
`RESTRICT` foreign keys that had just been fixed twice for tenant deletion. Unlike the tenant
case, this one is **not a corner case** — reproduced live on the very first real attempt: created
a tenant, had its Admin create an Analyst, had the Analyst log in and complete the mandatory
first-login password change (unconditional for every new account, per the hard provisioning
rule), then had the Admin delete that Analyst — immediate `500`,
`RefreshToken_userId_fkey`. Since every user must log in and change their password before doing
anything else, this meant **deleting essentially any real user was broken**, not just users
with unusual activity.

- Fixed with the same shape as the tenant-deletion fixes: `removeUserForTenant` now runs a
  `$transaction` array that clears `RefreshToken`/`PasswordHistory` (`where: { userId: id }`,
  same relation-scoping reasoning as §4.21 — neither table has a `tenantId` column) and nulls out
  `assignedToUserId` on all four assign-workflow tables (`SiemAlert`, `EdrDetection`,
  `DfirIncident`, `VmVulnerability` — each also `RESTRICT`s on `assignedToUserId`) before the
  `user.delete()` itself. Unassigning clears the FK, not the record — the alert/detection/
  incident/vulnerability itself is untouched, it just becomes unassigned.
- Verified live two ways: the exact failing scenario above (now succeeds), and a second case
  specifically exercising the `assignedToUserId` dimension — created another Analyst, walked a
  real EDR→SIEM chain to get a live alert, assigned it to that Analyst, then deleted the Analyst
  while the assignment was still active. Deletion succeeded; the alert survived with
  `assignedToUserId: null`.
- **One honest, minor finding, not fixed here**: that surviving alert kept `status: "ASSIGNED"`
  with a now-null assignee — an inconsistent combination the explicit `DELETE .../:id/assign`
  unassign endpoint (§4.19) always prevents by reverting status to `OPEN` in the same write. Bulk
  user-deletion cleanup only clears the assignee, not the status, for two reasons: (1) blindly
  reverting status to `OPEN` for *every* record assigned to the deleted user would be wrong for
  already-`RESOLVED`/`CONTAINED` ones — resolving deliberately does not clear `assignedToUserId`
  (§4.18, "resolving doesn't clobber the assignedToUserId set by the earlier assign", since it's
  kept as a "who resolved this" record), so a blanket revert would incorrectly reopen closed
  incidents; correctly scoping the revert to only `TRANSITIONABLE_STATUSES` rows adds meaningful
  complexity (a second conditional `updateMany` per table) for what's a rare
  administrative operation, not a user-facing action. (2) `AssetFeedEntry` also isn't synced for
  this path (no event emitted) — same "eventually consistent, dashboard feed, not source of
  truth" trade-off already accepted by the Phase 7 decision. Left as-is; revisit only if a real
  workflow depends on an ASSIGNED-with-no-assignee record never appearing.
- `users.service.spec.ts`'s `removeUserForTenant` tests rewritten for the `$transaction` shape
  (all six deletion/unassignment calls plus the final `user.delete()` asserted); no e2e changes
  needed (`test/users.e2e-spec.ts` mocks `UsersService` directly, not `PrismaService`, for this
  route). 447 unit / 168 e2e passing — unchanged, since this extended existing test cases rather
  than adding new ones.

# VmAsset/EdrEndpoint mutability gap closed (2026-08-06)

Found the same deliberate-completeness way as every finding above it, not a repeat of an earlier
answer. `VmAsset` had `POST`/`GET /vm/assets` only; `EdrEndpoint` didn't even have a manual
create route (only auto-upserted via `ingest()`) and had `GET /edr/endpoints` only — neither had
any `PATCH`/`DELETE`. Same category of gap as the CTI IOC/SOAR playbook one closed earlier: both
are pure inventory/reference data (a wrong hostname/IP, a decommissioned host, duplicate/test
data), not the deliberately-immutable event records (`SiemAlert`/`EdrDetection`/`DfirIncident`/
`VmVulnerability`) that only ever evolve through status/assignee by design.

- `PATCH /vm/assets/:id` and `PATCH /edr/endpoints/:id` (Analyst/Admin, matching each module's
  existing create-route RBAC) — editable fields only (`name`/`ip`/`type` for VM,
  `hostname`/`ip`/`os`/`status` for EDR).
- `DELETE /vm/assets/:id` and `DELETE /edr/endpoints/:id` (Analyst/Admin) — both guarded the same
  way `SoarService.deletePlaybook` already was: `VmVulnerability.assetId` and
  `EdrDetection.endpointId` both `RESTRICT` on their parent, so a naive hard delete would just be
  a fourth instance of the RESTRICT-FK bug class fixed three times above. Checked explicitly via
  `count()` before deleting; `409 Conflict` otherwise.
- `EdrEndpointStatus` gained a fourth value, `DECOMMISSIONED`, alongside the delete guard — the
  intended path for retiring a host that still has detection history, mirroring the `isActive`
  toggle `SoarPlaybook` got for the same reason. `VmAsset` has no equivalent lifecycle field;
  freeing one up for deletion means remediating or accepting-risk its vulnerabilities first,
  same as `SoarPlaybook`'s "no executions" requirement — no toggle invented for it, since nothing
  in the existing design suggested one was needed.
- Verified live: `PATCH`/`DELETE` on a fresh asset/endpoint with no children (both succeed);
  `DELETE` on one with a real child record (both correctly `409`, EDR's message pointing at the
  new `DECOMMISSIONED` status); `PATCH` to `DECOMMISSIONED` on the blocked endpoint (succeeds);
  tenant deletion afterward still cleanly tears down the new data (already covered by the
  existing `VmAsset`/`EdrEndpoint` entries in `deleteTenantWithUsers`'s dependency list, no
  changes needed there).
- Verified three ways: full unit + e2e suites (465 unit / 176 e2e, up from 447 + 168 — new
  `updateEndpoint`/`deleteEndpoint`/`updateAsset`/`deleteAsset` describe blocks across all four
  service/controller specs, plus `PATCH`/`DELETE` e2e route tests on both modules), typecheck and
  lint clean, and live against the real dev server + Postgres as described above. Regenerated the
  Prisma client explicitly after migrating (`npx prisma generate`, not just `migrate dev`) before
  starting the dev server this time, avoiding the stale-client gotcha hit in the CTI/SOAR pass.

# Full completeness scan (2026-08-06)

Requested explicitly as a single consolidated pass, rather than another one-gap-at-a-time round
— audited RBAC (every mutating route's `@Roles` guard, including class-level ones), DTO
validation (any remaining `@IsObject()`-style unvalidated fields), and every `.delete()`/
`.deleteMany()` call site against the full FK graph, in addition to the usual "what's still
create-only" sweep. RBAC and DTO validation both came back clean — every mutating route is
guarded (individually or via a controller-level `@Roles`), and the only remaining unvalidated
object field is `SoarPlaybook.actions`, already a deliberate, documented decision (§4.20 — no
real schema exists to validate against while SOAR execution is simulated). Four concrete findings
came out of the FK/CRUD sweep; three were fixed, one was found, attempted, and deliberately
reverted:

**1. `TenantModule` had zero API surface — the actual major finding.** Every reference to it
traced back to only two places: `PollingService` (reads/updates `isActive`), and the demo seed
script (the only writer). `TenantsService.createTenantWithAdmin` — the real provisioning path —
never touched it. Concretely: **every tenant created through the real API had zero
`TenantModule` rows, forever**, since nothing in the app ever wrote one outside the seed script.
Phase 9's scheduled polling skeleton had only ever been exercised against seed data — for a real
tenant, `where: { isActive: true }` silently matched nothing.
   - Fixed with a full CRUD surface under the existing `TenantsController` (already
     `@Roles(SUPER_ADMIN)`-gated at the class level, so no new RBAC boundary needed): `GET
     /tenants/:id/modules`, `POST` (activate — `{ moduleName, config? }`, `409` on duplicate via
     the same P2002-catch pattern used elsewhere), `PATCH /tenants/:id/modules/:moduleName`
     (`{ isActive?, config? }`), `DELETE` (remove entirely). `:moduleName` validated with Nest's
     built-in `ParseEnumPipe(ModuleName)` — a malformed value 400s before ever reaching the
     service.
   - Deliberately **not** auto-provisioned at tenant creation — root `CLAUDE.md` describes
     tenants as able to "activate the modules relevant to them," meaning which modules apply is
     a per-tenant decision, not a default every tenant gets. The new CRUD *is* that activation
     path; nothing about `createTenantWithAdmin` itself changed.
   - Verified live: a freshly created tenant's `GET .../modules` genuinely returns `[]` (the bug,
     confirmed first), then activate → `409` on a duplicate activate → `PATCH` deactivate →
     `DELETE` → `404` on a second delete → back to `[]`. Also confirmed the invalid-moduleName
     400 fires before the service is ever called.
- **2. `PATCH /tenants/:id`** — a tenant's name could never be corrected after creation. Added,
  `SUPER_ADMIN`-gated same as every other tenant route. Live-verified rename + 404 on a missing
  tenant + 403 for a non-Super-Admin.
- **3. `DELETE /dfir/incidents/:id/links/:linkId`** — `POST .../links` existed, nothing could
  ever remove a mistakenly-added link. Nothing references `DfirLink` (it's the leaf of the
  polymorphic link relationship), so — unlike the `SoarPlaybook`/`EdrEndpoint`/`VmAsset` deletes
  before it — this one needed no RESTRICT-FK guard, just tenant/incident/link ownership checks.
  Live-verified against a real orchestration-chain incident with two real auto-created links:
  deleted one, confirmed the other survived untouched, confirmed a second delete of the same
  link correctly 404s.
- **4. Attempted and reverted: `ParseUUIDPipe` on every `:id`/`:linkId` route param (29 call
  sites).** A malformed ID currently reaches Prisma unvalidated and surfaces as an uncaught `500`
  (via `AllExceptionsFilter`) instead of a clean `400` — a real but minor HTTP-semantics gap, not
  a functional defect (nothing crashes, no data corruption, the response body is still a clean
  JSON error). Applied the pipe everywhere, then ran the full e2e suite: **42 of 176 tests broke**
  — the entire existing e2e suite is built on human-readable pseudo-IDs (`'tenant-1'`,
  `'endpoint-1'`, `'ioc-1'`, ...) as its established fixture convention, not real UUID strings,
  across essentially every spec file. Fixing this properly would mean rewriting ID fixtures
  throughout the whole e2e suite — a large, mechanical, disruptive change for what's a
  status-code nicety. Reverted in full; not pursued further. If ever revisited, it should be a
  dedicated pass that rewrites e2e fixtures to real UUIDs first, not bundled into an unrelated
  change.
- Verified three ways for the three items that shipped: full unit + e2e suites (491 unit / 187
  e2e at the time — up from 465 + 176 — new `renameTenant`/`listModules`/`activateModule`/`updateModule`/
  `deactivateModule` describe blocks in both `tenants.service.spec.ts` and
  `tenants.controller.spec.ts`, `unlinkRecord`/`deleteLink` blocks in the DFIR specs, plus e2e
  route tests for all of it), typecheck and lint clean, and live against the real dev server +
  Postgres as described per-item above. No schema migration was needed this round —
  `TenantModule` already existed, so the earlier Prisma-client-regeneration gotcha didn't recur,
  though `npx prisma generate` was still run proactively before starting the dev server.
- **Test count stale, corrected 2026-08-19**: this section's "491 unit / 187 e2e" had gone stale
  — a live `npm test` re-run found **507 unit / 187 e2e**, all passing, with no corresponding
  entry in this file for what added the extra 16 unit tests (`frontend/CLAUDE.md`'s Phase-13
  audit entry attributes later backend-internal work — refresh-token race-condition hardening,
  atomic lockout counter, CTI ingest concurrency — but this file itself never logged it). Caught
  during a full live QA pass, not a code change; flagged here rather than silently left wrong,
  per this file's own "update it as reality diverges" rule. Re-verify the count directly with
  `npm test` before trusting either number if this looks stale again.

# API surface & operational hardening

- **`npm run lint` genuinely is clean now — found broken and fixed same-day, 2026-08-19.**
  A plain run had contradicted every "lint clean" claim in this file's phase-by-phase log:
  **73 real errors across 25 files**, none touched by the session that found this — core
  files including `auth.service.ts`, `jwt.strategy.ts`, `main.ts`, `users.controller.ts`, and
  most of `src/**/*.spec.ts`/`test/*.e2e-spec.ts`. The likely explanation for how it got this
  way unnoticed: those historical "lint clean" claims were asserted, not verified against a
  real `npm run lint` invocation — the exact gap this project's own "verify, don't assume"
  rule exists to catch; `eslint.config.mjs`'s ruleset and the installed
  `@typescript-eslint/eslint-plugin` version match what's locked in `package-lock.json`, so
  this wasn't dependency drift since those claims were written. Fixed the same day, in two
  parts:
  - **~55 of the 73 were `no-unsafe-assignment`/`-member-access`/`-call`/`-return` inside
    `*.spec.ts`/`*.e2e-spec.ts` files, and turned out not to be real application bugs at
    all** — traced to Jest's own type defs: `expect.any(...)`/`expect.objectContaining(...)`
    are typed `any` (there's no way for them to know what you're matching against ahead of
    time), so asserting against a realistically-shaped mock call trips "unsafe" on every
    matcher, in every spec file. Scoped `no-unsafe-*` off for test files only, via a
    `files: ['**/*.spec.ts', 'test/**/*.e2e-spec.ts']` override block in `eslint.config.mjs` —
    application source code keeps the full `recommendedTypeChecked` ruleset unchanged.
  - **The remaining ~18 were real, and fixed as real code changes**, all re-verified live
    against the running dev server, not just by re-running the linter: `context.switchToHttp
    ().getRequest()` typed explicitly as `Request & { user?: AuthenticatedUser }` in both
    `JwtAuthGuard` and `RolesGuard` (confirmed live: a valid Super Admin token still gets
    `200` from `GET /tenants`, no token still gets `401`, a wrong-role token still gets
    `403` — the retyping changed nothing about the actual guard behavior, only how TypeScript
    sees it); every `@Transform(({ value }) => ...)` callback across the three email/phone-
    normalizing DTOs (`LoginDto`, `ForgotPasswordDto`, `CreateUserDto`) explicitly typed as
    `{ value: unknown }` instead of the implicit `any` class-transformer's own
    `TransformFnParams` declares; `JwtStrategy.validate` de-asynced (no `await` inside it to
    begin with — Passport accepts a plain return just as well as a `Promise`); `main.ts`'s
    `declare const module: any` (the webpack-HMR `module.hot` shim, copied from NestJS's own
    HMR boilerplate) replaced with a real minimal type instead of `any`, plus `void bootstrap
    ()` and `void app.close()` at its two previously-floating-promise call sites; and every
    `const { hashedPassword, ...safeX } = user`-shaped destructure across `auth.service.ts`,
    `tenants.service.ts`, and `users.controller.ts` (9 call sites, all the exact same
    strip-the-hash-before-responding pattern) renamed to `hashedPassword: _hashedPassword` —
    paired with a new `varsIgnorePattern: '^_'`/`argsIgnorePattern: '^_'` config for
    `no-unused-vars`, since a leading underscore marking "deliberately unused" is the
    idiomatic fix for a destructure-only-to-discard binding, not a real dead-code smell to
    silence per call site.
  - Re-verified all four ways after: `npm run lint` (0 errors, 0 warnings), `tsc --noEmit`
    clean, `prettier --check` clean, and the full suite (507 unit / 187 e2e) still green —
    plus the live guard-behavior check above, since two of the fixed files are the app's
    actual security boundary, not just internal logic. Going forward, don't assume a future
    "lint clean" claim in this file without re-running `npm run lint` for real — that's
    exactly the assumption that let this go unnoticed.
- All routes are served under a global `/api` prefix (`app.setGlobalPrefix('api')` in
  `main.ts`) — e.g. `POST /api/auth/login`, not `POST /auth/login`. Any new e2e test must
  hit paths under `/api/...`.
- `GET /api/health` — public (`@Public()`, bypasses JWT), backed by `@nestjs/terminus`.
  Aggregates three independently-reported checks: `database` (a real Prisma ping query,
  not just "is the process alive"), `memory_heap`, `memory_rss` (300MB threshold each).
  Returns `200` with all components `up`, or `503` with the failing component(s) isolated
  under `error` while healthy ones stay under `info` — this is what makes it useful for
  debugging: an on-call engineer immediately sees *which* dependency broke instead of just
  "something's down." Deliberately one aggregate endpoint with a per-component breakdown,
  not one route per module — `users`/`tenants`/`auth` all share the same single failure
  mode today (Postgres down), so a per-module route would just triplicate the same check.
  Add new named indicators here (not new routes) once modules gain their own independent
  external dependencies (e.g. SIEM's Elastic cluster).
- `helmet()` in `main.ts` sets standard security response headers (CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, etc.). HSTS is explicitly configured (not left at helmet's
  default) with `maxAge: 63072000` (2 years), `includeSubDomains: true`, and `preload: true`
  — the `preload` flag alone does nothing without the extra manual step of submitting the
  production domain at hstspreload.org; do that only once the production domain is final,
  since preload-list removal is slow (tied to browser release cycles) and effectively
  permanent in practice. Never submit a dev/staging domain by mistake.
- CI (`.github/workflows/test.yml`) runs `npx prisma generate` before `npx prisma migrate
  deploy` / `npm test` / `npm run test:e2e`. This is required, not optional: `src/generated/
  prisma` is gitignored, and `migrate deploy` only applies SQL migrations — it does not
  generate the TypeScript client. Without this step every suite importing from
  `../generated/prisma/*` fails with `Cannot find module` on a clean checkout (this exact
  failure happened and was diagnosed via CI logs before the fix was added).
- Frontend types are hand-maintained (not generated) to match the shapes documented in
  root `CLAUDE.md`'s "Backend API contract" section — deliberate choice, safest option for
  a production API surface, at the cost of manual sync when a DTO changes.
- `npm audit` flags one moderate vulnerability in `@hono/node-server`, pulled in transitively
  through `@prisma/dev` (Prisma's CLI dev tooling, not a runtime dependency of the deployed
  app). The available fix requires downgrading `prisma` to `6.19.3` — a breaking change
  against this project's Prisma-7-specific work (driver adapter, `moduleFormat: cjs`,
  `prisma.config.ts` seed wiring, etc., see `docs/internship-report-backend.md` §4.1/§4.11).
  Left deliberately unfixed; don't `npm audit fix --force` this away.

# Platform readiness (2026-08-19)

The backend is functionally complete and live-tested, not just implemented on paper: a full
manual QA pass (login/lockout, tenant CRUD, user CRUD + password-reset-request flow, every
module's ingest/query/assign/status-transition routes, the full EDR→SIEM→CTI→SOAR→DFIR
orchestration chain, live SSE, RBAC across all 4 roles, tenant isolation) was run against a
real seeded dev DB and confirmed working end-to-end; every finding from that pass and the
73-error lint-debt discovery above were fixed and re-verified the same day. `npm run lint`,
`tsc --noEmit`, `prettier --check`, and the full suite (507 unit / 187 e2e) are all clean.

~~What's actually left is infrastructure, not functionality: No Dockerfile... CI is
test-only...~~ **No longer true, fixed 2026-08-21/22.** `backend/Dockerfile` is a real
multi-stage build (`builder`/`migrator`/`runner`, `node:22-slim`), live-tested against the
real dev Postgres and, since the `migrator` split, down to 515MB for the always-running
`runner` image — see `../DOCKERIZATION_TODO.md` at the repo root for the full phase-by-phase
build log, every claim in it backed by a live verification, not just written and assumed.
`docker-compose.yml` (also moved to the repo root, orchestrating both `backend` and
`frontend`) and `docker-compose.image.yml` (the `image:`-reference variant for CI/deploy) both
exist and were live-run end to end: Postgres → migrate → backend all healthy, a real login
through the full compose stack, and a real EDR→SIEM SSE event pair delivered live through the
containerized stack. CI is no longer test-only either — `.github/workflows/build.yml` (Sonar
scan, then on a real push to `main`, build+push three images to GHCR) and `deploy.yml`
(SSH-deploys `migrate`+`backend` to an Azure VM, triggered by `build.yml` succeeding) now sit
alongside the pre-existing `test.yml`. See `../CICD_SETUP.md` for the secrets/one-time-VM-setup
checklist this needed — that checklist's own completion (have the GitHub secrets actually been
added, has the VM actually been provisioned) isn't independently confirmed from this repo
alone, verify directly rather than assuming a green Actions tab. **Left, still genuinely
infra not functionality**: no pre-commit/husky hooks (lint/typecheck/format only run manually
or in CI).

The one still-open *functional* gap (not infra) is real vendor API integration for the six
modules — see "Security modules architecture" above; every module currently ingests from a
`MockAdapter`, deliberately, pending real API docs. That's a data-source question, not a
readiness blocker for Dockerizing/deploying what's built.

# Conventions

- Don't guess at vulnerabilities or root causes — enumerate and verify first
- Manual, step-by-step fix instructions preferred over full file replacements when debugging
  existing configs/workflows (preserves credentials and state)

# Module implementation plan — SIEM / SOAR / CTI / EDR / DFIR / VM

**How to use this checklist:** one unchecked item is roughly one chat session's worth of work.
Pick the next unchecked box, implement it yourself, come back for review — check the box only
once it's actually reviewed and working, not just attempted, so this list stays trustworthy.
Update it as reality diverges from the plan (a phase turns out to need splitting, a decision
below gets overridden, etc.) — don't let it silently drift, same rule as every other list in
this file. Every module task implicitly includes its own migration
(`npx prisma migrate dev --name <phase>_<what>`) — not called out per line.

**Build order:** VM first as a warm-up (no cross-module orchestration — nail the
schema→service→controller→tests rhythm once, cleanly, before adding event-emitter complexity).
Then EDR → SIEM → CTI → SOAR → DFIR in the spec's own orchestration order, so each module's
"listen for the previous module's event" step is built right when the module it depends on
already exists, instead of one big wiring task at the end. Asset aggregation, SSE, and the
polling-ingestion skeleton come after all six modules exist, since they all read across modules.

## Decisions baked into this plan — confirm or override before starting, don't silently accept

1. **`Severity` becomes a real Prisma enum**, `LOW | MEDIUM | HIGH | CRITICAL` (uppercase),
   matching this codebase's existing enum casing (`UserRole`, `ModuleName`, `ModuleSourceType`)
   rather than the architecture PDF's lowercase `'low' | 'medium' | ...` strings. The TS
   `Severity` type should mirror the Prisma enum 1:1 (no manual mapping layer at the API
   boundary) — this is a deliberate, documented deviation from the PDF spec's example casing,
   not an oversight.
2. **`source` reuses the existing `ModuleName` enum** (`SIEM | SOAR | CTI | EDR | DFIR | VM`)
   instead of introducing a second, near-identical `EventSource` enum — the PDF's extra `'api'`
   source value is dropped; a manually-entered record (e.g. an Admin hand-adding a CTI IOC) can
   just use that module's own name as its source. Revisit only if a real need for a distinct
   "manual/API" source shows up.
3. **Every per-record table gets a `rawData Json?` column**, extending the pattern the spec
   already applies to `siem_logs` (`raw_data`) to every module — this is what makes the
   `UnifiedEvent.data` escape hatch meaningful: known fields get real relational columns
   (queryable, indexable), the full original payload is never silently dropped.
4. **Shared types live in `src/common/security-module/`** (`types.ts` for `Severity`,
   `UnifiedEvent`, `ModuleHealth`, `BaseQueryFilters`; `security-module.interface.ts` for the
   `SecurityModule<TRecord, TFilters>` contract) — new folder, since nothing shared currently
   exists outside `src/auth`/`src/users`/`src/tenants`/`src/prisma`/`src/health`.
5. **`SecurityModule` is generic**, not the PDF's literal `query(filters): Promise<any[]>`:
   `interface SecurityModule<TRecord, TFilters extends BaseQueryFilters> { ingest(event:
   UnifiedEvent): Promise<void>; query(filters: TFilters): Promise<TRecord[]>; healthCheck():
   Promise<ModuleHealth> }` — closes the one real type-safety gap in the spec's interface.
6. **Cross-module reactions go through the event emitter only, never a direct service-to-service
   call** (e.g. CTI never imports `SiemService` directly to escalate a severity — it emits
   `cti.enrichment.applied` and SIEM listens for it). Keeps the modules as decoupled in code as
   the architecture doc claims they are conceptually.
7. **Ingestion routes (`POST /<module>/events`) are temporarily gated behind the existing
   `@Roles(ADMIN)` JWT auth, as a stand-in.** A real EDR agent or vendor webhook won't have a
   tenant user's JWT — it needs its own auth (API key, mTLS, etc.). Designing that is a separate,
   deliberate decision, not something to improvise as a side effect of building these routes;
   flagged here so it isn't forgotten, not solved in this plan.

   **Tracked gap, parked 2026-08-05 — not scheduled, revisit only when a real
   machine caller exists.** Designed but deliberately not built, once the actual shape became
   clear: an `ApiKey` model (`tenantId, moduleName, keyHash, keyPrefix, lastUsedAt, revokedAt`,
   SHA-256 hashed same reasoning as `RefreshToken`) plus a guard accepting `X-API-Key` on these
   four routes as an alternative to a human JWT. The complexity that argued against building it
   now: it's not a route-level addition — `JwtAuthGuard`/`RolesGuard`/`MustChangePasswordGuard`
   are all global (`APP_GUARD` in `app.module.ts`), so a second credential type means teaching
   the guard chain every route depends on to recognize it (`JwtAuthGuard` would need a new
   `@AllowApiKey(ModuleName.X)` decorator, `RolesGuard` would need to skip `@Roles(ADMIN)` for
   a synthetic api-key-authenticated request without loosening it for real JWTs) — real blast
   radius on the app's highest-traffic security surface, for a caller that, like the real vendor
   integrations themselves, doesn't exist yet. Two options when this is picked back up:
   - **Preferred if/when built**: a separate `POST /ingest/<module>` namespace gated only by a
     standalone `ApiKeyGuard` (`@Public()` from `JwtAuthGuard`'s perspective, since the key fully
     replaces JWT auth), calling the same `<Module>Service.ingest()`. Zero risk to the existing
     global guard chain, at the cost of two URLs reaching the same ingestion logic.
   - Full integration into the existing `POST /<module>/events` routes (the `@AllowApiKey`
     decorator approach above) — cleaner surface, more invasive, only worth the risk once a real
     caller's needs (e.g. it must be the *same* URL a vendor's webhook config expects) demand it.
8. **SOAR "execution" is fully simulated for MVP** — `SoarExecution` rows are created and
   immediately marked `SUCCESS` with a logged message; there is no real automation engine to call
   (per root `CLAUDE.md`: the backend integrates external engines, it doesn't reimplement them,
   and no real SOAR engine access exists yet). Don't build fake "real" execution logic.
9. **RBAC default across all six modules**, unless a task below says otherwise: any
   authenticated tenant role (Admin/Analyst/Viewer) can `GET`; mutating/status-changing routes
   require `@Roles(ANALYST, ADMIN)` (matches the spec's "Analyst investigates, can trigger SOAR;
   Viewer is read-only" role description); Super Admin has no tenant, so no module routes apply
   to it, same as the existing `[module]` stub's reasoning on the frontend.
10. **`TenantModule.sourceType` (`PLATFORM | OWN`) and the `ModuleSourceType` enum are removed
    from the schema entirely — decided 2026-08-04.** Considered keeping it unused-but-present
    first, then decided against: not valuable for MVP (every module is treated as Gérance-
    provided), and a repo-wide grep confirmed zero code anywhere referenced it. If a
    tenant-brings-their-own-external-account scenario becomes real later, re-add it then — a
    single nullable-enum-column migration is cheap, and there's nothing to reconcile since
    nothing was ever built against it.
11. **The Asset feed is a materialized table (`AssetFeedEntry`), not a live fan-out query —
    decided 2026-08-05.** Phase 7 was originally planned as `AssetService.getUnifiedFeed` calling
    each module's `query()` live and merging + sorting in application code before paginating.
    Rejected once multi-tenant production-scale pagination was considered: merging six tables'
    worth of matching rows in memory on every page request doesn't scale, and offset pagination
    over an in-memory merge can't be fixed by "just add an index" the way DB-level pagination can.
    Instead, every module emits a `*.created` event on **every** new record — not just the
    orchestration-relevant events that already exist — and `AssetService` listens for all of them,
    writing a denormalized row into its own table. `getUnifiedFeed` becomes one indexed, real
    `ORDER BY timestamp LIMIT/OFFSET` query. Trade-off accepted deliberately: the feed is
    eventually-consistent with its source tables (fine for a dashboard feed, would not be fine as
    a source of truth) in exchange for genuine DB-level pagination. A raw SQL `UNION ALL` across
    all six tables was considered and rejected again for the same reason as the original phase
    text: it couples `AssetService` to every module's physical schema, breaking the decoupling
    decision 6 exists to protect.

## Phase 0 — Foundation (do this before any module)

- [x] **Phase 0.0 — Remove `TenantModule.sourceType` and the `ModuleSourceType` enum from
      `schema.prisma`** (decision 10 above). Delete the `sourceType ModuleSourceType
      @default(PLATFORM)` field from `TenantModule` and the `enum ModuleSourceType { PLATFORM
      OWN }` block entirely, then `npx prisma migrate dev --name remove_module_source_type`.
      Nothing else in the codebase references either symbol (verified via repo-wide grep), so
      this is a clean, self-contained removal with no follow-on edits anywhere else.
- [x] Install `@nestjs/event-emitter` and `@nestjs/schedule`; wire `EventEmitterModule.forRoot()`
      and `ScheduleModule.forRoot()` into `AppModule`.
- [x] `src/common/security-module/types.ts` — `Severity` (also add as a Prisma enum in
      `schema.prisma`), `UnifiedEvent { tenantId, timestamp, source: ModuleName, type, severity,
      data: Record<string, unknown> }`, `ModuleHealth { module, status, lastIngestion? }`,
      `BaseQueryFilters { tenantId, severity?, dateFrom?, dateTo?, page?, pageSize? }`.
- [x] `src/common/security-module/security-module.interface.ts` — the generic `SecurityModule`
      contract from decision 5 above.
- [x] `src/common/dto/base-query.dto.ts` — the `class-validator` DTO twin of
      `BaseQueryFilters`, for controllers to extend (mirrors the existing `ListUsersQueryDto`
      pagination pattern in `src/users/dto/`).
- [x] Unit test for nothing yet (no logic in this phase) — just confirm `npx nest start` still
      boots cleanly with the two new global modules registered.

## Phase 1 — VM module (warm-up, no orchestration dependency)

- [x] Prisma: `VmAsset { id, tenantId, name, ip, type, createdAt }`, `VmVulnerability { id,
      tenantId, assetId, severity Severity, description, cveId String?, status enum (OPEN |
      REMEDIATED | ACCEPTED_RISK, default OPEN), rawData Json?, createdAt }`. Index `tenantId`
      on both, per this project's existing convention.
- [x] `VmService implements SecurityModule<VmVulnerability, VmQueryFilters>`:
      `ingest(event)` (upsert `VmAsset` by `(tenantId, ip)` if `data` references one, then create
      `VmVulnerability`), `query(filters)`, `healthCheck()`, `listAssets(tenantId)`,
      `createAsset(tenantId, dto)`, `updateVulnerabilityStatus(tenantId, id, status)`.
      + `vm.service.spec.ts` (mocked `PrismaService`, same pattern as `users.service.spec.ts`).
- [x] `VmController`: `GET /vm/assets`, `POST /vm/assets` (Analyst/Admin), `GET
      /vm/vulnerabilities` (query-param filters), `PATCH /vm/vulnerabilities/:id/status`
      (Analyst/Admin), `POST /vm/events` (ingestion, Admin-gated per decision 7).
      + `vm.controller.spec.ts` (mocked service).
- [x] `test/vm.e2e-spec.ts` — full HTTP through the real guard chain, mocked `PrismaService` at
      module level (same pattern as `test/users.e2e-spec.ts`/`test/tenants.e2e-spec.ts`).

## Phase 2 — EDR module

- [x] Prisma: `EdrEndpoint { id, tenantId, hostname, ip, os, status, lastSeen }`,
      `EdrDetection { id, tenantId, endpointId, detectionName, severity Severity, rawData Json?,
      createdAt }`.
- [x] `EdrService implements SecurityModule<EdrDetection, EdrQueryFilters>`: `ingest(event)`
      (upsert `EdrEndpoint` by `(tenantId, hostname)`, create `EdrDetection`, then
      `eventEmitter.emit('edr.detection.created', event)`), `query()`, `healthCheck()`,
      `listEndpoints(tenantId)`. + `edr.service.spec.ts` (assert the emit call happens, via a
      mocked `EventEmitter2`).
- [x] `EdrController`: `POST /edr/events` (ingestion), `GET /edr/endpoints`, `GET
      /edr/detections`. + `edr.controller.spec.ts`.
- [x] `test/edr.e2e-spec.ts`.

## Phase 3 — SIEM module (listens to EDR)

- [x] Prisma: `SiemLog { id, tenantId, source, eventType, severity Severity, rawData Json?,
      timestamp }`, `SiemAlert { id, tenantId, title, severity Severity, status enum (OPEN |
      ASSIGNED | ESCALATED | RESOLVED, default OPEN), assignedToUserId String?, rawData Json?,
      createdAt }`.
- [x] `SiemService implements SecurityModule<SiemAlert, SiemQueryFilters>`: `ingest(event)`
      (always writes `SiemLog`; creates a `SiemAlert` too when `type === 'alert'` or severity is
      HIGH/CRITICAL — keep the threshold simple and explicit for MVP, it's meant to be revisited,
      not a clever heuristic), `query()`, `healthCheck()`, `updateAlertStatus(tenantId, id,
      status, assignedToUserId?)`. + `siem.service.spec.ts`.
- [x] `@OnEvent('edr.detection.created') handleEdrDetection(event: UnifiedEvent)` on
      `SiemService` — turns an EDR detection into a `SiemAlert`, then emits
      `siem.alert.created`. + unit test asserting the listener fires and produces the alert.
- [x] `SiemController`: `POST /siem/events`, `GET /siem/logs`, `GET /siem/alerts`, `PATCH
      /siem/alerts/:id` (assign/escalate/resolve — Analyst/Admin only, Viewer blocked, matching
      the frontend's already-deferred "no row-level actions until a real SIEM module exists").
      + `siem.controller.spec.ts`.
- [x] `test/siem.e2e-spec.ts` — include a test that actually POSTs an EDR event and asserts a
      `SiemAlert` shows up via `GET /siem/alerts` (first real cross-module integration test).

## Phase 4 — CTI module (enriches SIEM alerts)

- [x] Prisma: `CtiIoc { id, tenantId, type, value, confidence, source, rawData Json?,
      createdAt }`.
- [x] `CtiService implements SecurityModule<CtiIoc, CtiQueryFilters>`: `ingest(event)`,
      `query()`, `healthCheck()`, `checkMatch(tenantId, value): Promise<CtiIoc | null>`.
      + `cti.service.spec.ts`.
- [x] `@OnEvent('siem.alert.created') handleSiemAlert(event)` on `CtiService` — pulls a
      matchable value out of `event.data`, calls `checkMatch`; on a hit, emits
      `cti.enrichment.applied` carrying the escalated severity (per decision 6 — CTI never calls
      `SiemService` directly). + unit test for both the match and no-match paths.
- [x] `SiemService` gains `@OnEvent('cti.enrichment.applied') handleEnrichment(...)` — applies
      the escalated severity to the referenced `SiemAlert`. + unit test.
- [x] `CtiController`: `POST /cti/iocs` (manual entry, Analyst/Admin), `GET /cti/iocs`, `POST
      /cti/events`. + `cti.controller.spec.ts`.
- [x] `test/cti.e2e-spec.ts` — include the full chain: EDR event → SIEM alert → CTI match →
      alert severity escalated.

## Phase 5 — SOAR module (triggers off SIEM/CTI)

- [x] Prisma: `SoarPlaybook { id, tenantId, name, triggerCondition Json, actions Json,
      createdAt }`, `SoarExecution { id, tenantId, playbookId, alertId, status enum (PENDING |
      RUNNING | SUCCESS | FAILED), logs String?, createdAt }`.
- [x] `SoarService implements SecurityModule<SoarExecution, SoarQueryFilters>`: `ingest()`,
      `query()`, `healthCheck()`, `evaluateTriggers(tenantId, event: UnifiedEvent)` (loads active
      playbooks, does a simple exact-match check of `triggerCondition` against the event —
      e.g. `{ severity: 'CRITICAL' }` — creates a `SoarExecution` row, simulated per decision 8,
      then emits `soar.execution.created`). + `soar.service.spec.ts`.
- [x] `@OnEvent('siem.alert.created')` and `@OnEvent('cti.enrichment.applied')` on `SoarService`
      → both call `evaluateTriggers`. + unit tests.
- [x] `SoarController`: `GET /soar/playbooks`, `POST /soar/playbooks` (Admin only — playbooks are
      configuration, not day-to-day analyst work), `GET /soar/executions`. +
      `soar.controller.spec.ts`.
- [x] `test/soar.e2e-spec.ts`.

## Phase 6 — DFIR module (aggregates everything)

- [x] Prisma: `DfirIncident { id, tenantId, title, severity Severity, status enum (OPEN |
      INVESTIGATING | CONTAINED | RESOLVED, default OPEN), createdAt }`, `DfirLink { id,
      incidentId, sourceType, sourceId }` (polymorphic — `sourceType` is a `ModuleName` plus
      `'soar_execution'`/whatever record kind, `sourceId` is that record's id, no FK constraint
      since it points across tables by design, same shape as the spec).
- [x] `DfirService implements SecurityModule<DfirIncident, DfirQueryFilters>`: `ingest()`,
      `query()`, `healthCheck()`, `createIncidentFromEvent(tenantId, event, links:
      {sourceType, sourceId}[])`, `linkRecord(incidentId, sourceType, sourceId)`,
      `getIncidentDetail(tenantId, id)` (incident + its `DfirLink[]`, this is the data behind
      the spec's Figure 4 incident-detail screen), `updateStatus(tenantId, id, status)`.
      + `dfir.service.spec.ts`.
- [x] `@OnEvent('soar.execution.created') handleSoarExecution(event)` on `DfirService` — creates
      an incident, links the originating alert and the SOAR execution. + unit test.
- [x] `DfirController`: `GET /dfir/incidents`, `GET /dfir/incidents/:id`, `PATCH
      /dfir/incidents/:id` (status transitions, Analyst/Admin), `POST
      /dfir/incidents/:id/links`. + `dfir.controller.spec.ts`.
- [x] `test/dfir.e2e-spec.ts` — the big one: POST an EDR event and assert the *entire* chain
      lands a `DfirIncident` with links back to the SIEM alert and the SOAR execution.

## Phase 7 — Asset aggregator (materialized feed table, decision 11)

- [x] Prisma: `AssetFeedEntry { id, tenantId, source ModuleName, type String, severity Severity,
      timestamp DateTime, summary String, sourceId String, createdAt DateTime @default(now()) }`.
      Index `(tenantId, timestamp)` — this is the query this whole table exists to serve.
      Migration `20260805101609_add_asset_feed_entry` applied.
- [x] Give every module a `*.created` event covering **every** record-creation path, not just the
      orchestration-relevant ones decision 6's existing events cover. Each module needed a real
      fix along the way, found while wiring its listener — not one of the six was a clean
      "just subscribe" case:
      - **EDR** (`edr.detection.created`, reused): was re-emitting the raw incoming `UnifiedEvent`
        unchanged, so it never carried the created `EdrDetection`'s `id`. Fine for SIEM's existing
        listener (doesn't need it), not fine for `AssetService` (needs a `sourceId`). Fixed in
        `EdrService.ingest` by adding `detectionId: detection.id` into the emitted event's `data`,
        mirroring the `data.alertId` pattern SIEM's own emit already used.
      - **SIEM** (`siem.alert.created`, reused; `siem_logs` excluded — too raw/noisy for the feed):
        the emitted payload spread the *original* input `data`, so when no `title` was supplied
        and `SiemAlert.title` fell back to `` `${event.source} ${event.type}` ``, the emitted
        `data.title` stayed `undefined` while the real persisted title was the fallback string.
        Fixed by emitting the resolved `alert.title` instead of the raw input (DFIR's `ingest()`
        independently duplicates that same fallback logic today — pre-existing, unrelated code
        path, left alone).
      - **SOAR** (`soar.execution.created`, reused): the existing `SoarExecutionPayload` carried
        no `severity`, `timestamp`, or playbook name at all — it was built only for DFIR's needs
        (`alertId`/`executionId`). Extended the interface with `playbookName`, `severity`,
        `timestamp` (sourced from `execution.createdAt`); safe to extend since DFIR's listener
        doesn't do strict payload equality anywhere.
      - **VM** (`vm.vulnerability.created`, new): turned out there is no manual
        vulnerability-creation route at all (only `POST /vm/assets` for assets and
        `POST /vm/events` for ingestion, both funnel through `ingest()`) — the plan's "both
        `ingest()` and the manual path" text was written speculatively before checking; corrected
        to a single emit point in `ingest()`, same single-path situation as DFIR. `VmService`
        gained an `EventEmitter2` dependency it didn't have before.
      - **CTI** (`cti.ioc.created`, new): `POST /cti/iocs` and `POST /cti/events` both already
        funnel through the same `ingest()` (no separate manual-create method existed, unlike the
        plan assumed) — but `ingest()` uses `upsert()`, and a re-ingested/re-submitted IOC that
        only refreshes `confidence`/`source` shouldn't fire `*.created` again. Added a
        `findUnique` pre-check so the event only emits on genuine creation, not on every update.
      - **DFIR** (`dfir.incident.created`, new): emitted from `createIncidentFromEvent`, the one
        choke point both `ingest()` and `handleSoarExecution` already funnel through — single
        clean emit point, no duplication needed. Added a new `DfirIncidentPayload` type
        (`tenantId, incidentId, title, severity, timestamp`) since, like SOAR, there's no
        `UnifiedEvent` naturally in scope at that call site. `DfirService` gained an
        `EventEmitter2` dependency it didn't have before.
- [x] `AssetService` (new module, `src/asset/`) — `@OnEvent()` listener per event above, each
      mapping its module-specific payload down to the shared `{ source, type, severity, timestamp,
      summary, sourceId }` shape and writing an `AssetFeedEntry` row. `type` is always a hardcoded
      literal per listener (`'detection'`, `'alert'`, `'execution'`, `'vulnerability'`, `'ioc'`,
      `'incident'`) describing what was just created, not forwarded from the triggering event's
      own `type` field — that field isn't reliable for this (SIEM alerts can be created by
      `type: 'event'` inputs when severity alone crosses the threshold) and `AssetFeedEntry.type`
      is deliberately a plain `String`, not the ingestion-side `EventType`, precisely because it
      needs to describe record kinds (`'incident'`, `'execution'`) that `EventType` doesn't cover.
      `AssetModule` wired into `AppModule`. The four stateful e2e mocks that drive events through
      the real `EventEmitter2` (`siem`/`cti`/`soar`/`dfir`.e2e-spec.ts) each got an
      `assetFeedEntry.create` stub added (same test-isolation issue as Phase 6.5 — a newly
      globally-wired module's listener throwing silently inside other suites' event chains); the
      three that also call `POST /cti/iocs` in their stateful chain (`cti`/`soar`/`dfir`.e2e-spec)
      additionally needed a `ctiIoc.findUnique` stub once `CtiService.ingest` started calling it.
      + `asset.service.spec.ts` (one test per listener, asserting the write and the projected
      shape — no need to mock the other five services, just the event payload in and the Prisma
      call out).
- [x] `AssetService.getUnifiedFeed(tenantId, filters: BaseQueryFilters)` — a single
      `prisma.assetFeedEntry.findMany` with real `ORDER BY timestamp DESC` + `LIMIT/OFFSET`
      pagination and the standard severity/date filters. + tests in `asset.service.spec.ts`
      (default pagination, severity filter, date-range filter, custom page/pageSize, return
      passthrough).
- [x] `AssetController`: `GET /assets/feed` (read-only, any authenticated tenant role per
      decision 9). Caught before wiring it in: route was `@Controller('asset')` (singular,
      should be `assets` to match this task's own `GET /assets/feed` and the "Asset aggregator"
      naming), and both its DTO/helper imports (`BaseQueryDto`, `requireTenantId`) used the
      `src/...`-absolute path form — same failure class as `asset.service.ts`'s earlier
      `browser` import bug, but this time not latent: both are genuine runtime values
      (`BaseQueryDto` as a real decorator-metadata class reference, `requireTenantId` as an
      actual function call), so unlike the type-only case this would have broken the moment
      Jest tried to load the file, not stayed silently masked. Fixed to relative paths, route
      fixed to `assets`, wired into `AssetModule`'s `controllers`. + `asset.controller.spec.ts`.
      **Also, before this task**: extracted the `requireTenantId` private method — duplicated
      identically across all six existing module controllers (vm/edr/siem/cti/soar/dfir) — into
      a single shared `src/common/require-tenant-id.ts` function, and switched every controller
      to import it instead of keeping its own copy, so `AssetController` didn't become a
      seventh duplicate.
- [x] `test/asset.e2e-spec.ts` — a route/RBAC block (mocked `AssetService`, matches the pattern
      of every other module's first `describe` block) plus the full-chain integration test:
      create a SOAR playbook and a matching CTI IOC, POST a real EDR event, then assert
      `GET /assets/feed` returns all 5 resulting entries (the manually-added CTI IOC plus one
      per chain hop: EDR detection, SIEM alert, SOAR execution, DFIR incident), all scoped to
      the caller's tenant, in non-increasing timestamp order. One assertion had to be loosened
      from the original plan text ("DFIR should be first") to a general non-increasing-order
      check — the chain runs fast enough in-test that `SoarExecution.createdAt` and
      `DfirIncident.createdAt` can tie at millisecond resolution, and a stable sort keeps
      insertion order for ties rather than reordering them; not a bug in `getUnifiedFeed`, a
      real property of millisecond-resolution timestamps under a fast synchronous test chain.
      Second test confirms a non-matching IOC still lands EDR/SIEM entries without ever
      reaching SOAR/DFIR. Stable across 3 consecutive full e2e runs. **Phase 7 complete —
      287 unit / 128 e2e passing.**

## Phase 8 — Real-time delivery (SSE)

- [x] New `src/events/` module — `EventsService.streamForTenant(tenantId)` (returns
      `Observable<MessageEvent>`) + thin `EventsController` (`@Controller('events')`,
      `@Sse('stream')` → `GET /api/events/stream`, delegates to the service via the shared
      `requireTenantId`). No `PrismaModule`/DB at all — this is a pure relay, the only service
      in the backend that doesn't touch the database.
      Explicit list chosen over `EventEmitterModule.forRoot({ wildcard: true })` (discussed and
      decided before writing this) — merges `fromEvent(...)` for the same six `*.created` events
      `AssetService` already listens to (EDR/SIEM/SOAR/DFIR/VM/CTI), not `cti.enrichment.applied`
      (an update to an existing alert, not a new record). Real bugs caught while building it:
      - `fromEvent`'s type-parameter overload for Node-style emitters (`EventEmitter2` matches
        `NodeCompatibleEventEmitter`, not the DOM `HasEventTargetAddRemove` shape) is deprecated
        in RxJS 7 — the Node-style handler signature is `(...args: any[]) => void`, so a type
        param there was never actually checked, just asserted. Fixed by calling `fromEvent`
        untyped and doing one explicit `map((event) => event as StreamableEvent)` right after
        the `merge`, rather than typing each `fromEvent` call — same trust boundary, stated once
        instead of six times, and doesn't trigger the deprecation.
      - Three of the six event-name strings were wrong when first written (`'vulnerability.created'`
        instead of `'vm.vulnerability.created'`, `'ioc.created'` instead of `'cti.ioc.created'`,
        and a `'cti-enrichment.created'` that didn't correspond to any real emitted event at all)
        — no compile error, since event names are just strings, but those subscriptions would
        have silently never fired. Fixed to the real emitted names.
      - `MessageEvent` wasn't imported at all initially, so it resolved against the global DOM
        `MessageEvent` type instead of `@nestjs/common`'s own simpler `{ data, id?, type?, retry? }`
        interface — fixed with an explicit import.
      + `events.service.spec.ts` (real `EventEmitter2` instance, not mocked — the point is to
      prove `fromEvent`'s actual behavior: same-tenant events pass through, other-tenant events
      are filtered out, all six event names are subscribed, and unsubscribing actually stops
      delivery) + `events.controller.spec.ts` (thin, mocked `EventsService`, matches every other
      controller spec's pattern). Wired into `AppModule`. 295 unit / 128 e2e passing.
- [x] Manual verification, done 2026-08-05 against a real running dev server + Postgres: created
      a fresh tenant/Admin via the Super Admin, opened `curl -N /api/events/stream` with that
      Admin's JWT, POSTed a real `POST /api/edr/events` from another terminal, and watched both
      the resulting EDR detection *and* the SIEM alert it triggers arrive live on the open
      stream, correctly shaped (`id:`/`data:` SSE frames) and correctly attributed to the
      tenant. Went further than the plan's minimum and also verified the tenant-isolation
      requirement directly (the entire reason this phase exists): opened a second stream as a
      second tenant's Admin and confirmed it stayed completely silent while the first tenant's
      event fired — proves the `filter` in `EventsService.streamForTenant` actually holds under
      a real HTTP connection, not just in the unit test's synthetic `EventEmitter2`.
      **Unrelated bug found during cleanup, not fixed here**: `DELETE /api/tenants/:id` throws a
      500 (`FK constraint ... RESTRICT ... EdrEndpoint_tenantId_fkey`) for any tenant that has
      ever ingested data through any of the six security modules. `TenantsService.
      deleteTenantWithUsers` only deletes `User` and `TenantModule` rows before deleting the
      `Tenant` — written back in the original Auth/Tenants phase, before any module tables
      existed, and never revisited once they were added. Every module table's `tenantId` FK is
      `RESTRICT` (Prisma's default), so tenant deletion has been silently broken for any
      tenant with real module data since Phase 1. **Fixed 2026-08-05, immediately after Phase 8**
      (tracked separately, not folded into this phase's own checkbox since it's unrelated to
      SSE): `deleteTenantWithUsers` now explicitly deletes all twelve module tables — plus
      `DfirLink` — inside its existing `$transaction` array, in dependency order (children
      before the parents they reference: `AssetFeedEntry, DfirLink, DfirIncident,
      SoarExecution, SoarPlaybook, SiemAlert, SiemLog, EdrDetection, EdrEndpoint, CtiIoc,
      VmVulnerability, VmAsset`, then `TenantModule, User, Tenant` — `SiemAlert` before `User`
      specifically, since an alert can optionally reference its `assignedToUser`). Chose this
      over `onDelete: Cascade` in `schema.prisma` deliberately: this codebase has never used
      cascade on any of its ~18 relations, this keeps that record intact, and a destructive
      operation like "wipe a tenant's entire security history" stays confined to one reviewed
      service method rather than firing implicitly from any future code path that touches
      `Tenant.delete()`. Verified against the real dev database (the exact same order, run live
      during this phase's own cleanup, successfully deleted a tenant carrying real EDR/SIEM/
      Asset-feed data). `tenants.service.spec.ts` gained a full-coverage test (every table
      called with the right `tenantId`) and an explicit ordering test (tracks call order via a
      shared array, asserts each dependency constraint); `test/tenants.e2e-spec.ts`'s mocked
      `PrismaService` and fixed `$transaction` resolved array both updated to match. 296 unit /
      128 e2e passing.
      **Found 2026-08-06, fixed the same day.** `RefreshToken` and `PasswordHistory` (both added
      the same day as the fix above, in the auth-hardening work) were never retrofitted into
      `deleteTenantWithUsers`'s dependency list either, and both also have a `RESTRICT` FK on
      `userId`. `DELETE /api/tenants/:id` threw the identical 500 for any tenant whose users had
      ever logged in with a refresh-token session (`RefreshToken_userId_fkey`) or gone through a
      forced/self password change or an Admin-initiated reset
      (`PasswordHistory_userId_fkey`) — which in practice is every real tenant, since every new
      user is created with `mustChangePassword: true` and must change it before doing anything
      else. First found incidentally while cleaning up an unrelated live-verification tenant
      (a freshly-created tenant whose Admin had only logged in and completed the mandatory
      password change, no module data at all, still failed twice in a row, once per table).
      Fixed by extending the same `$transaction` array with both tables — `refreshToken.
      deleteMany`/`passwordHistory.deleteMany` filtered via the `user: { tenantId }` relation
      field rather than a direct `tenantId` column (neither table has one; both are scoped by
      `userId`), placed right before `user.deleteMany` since that's the row they both reference.
      Verified live: recreated the exact failing scenario (fresh tenant → Admin login → mandatory
      password change) and confirmed `DELETE /api/tenants/:id` now succeeds in one call, then
      confirmed via `GET /api/tenants` that the tenant is genuinely gone.
      `tenants.service.spec.ts`'s full-coverage and ordering tests extended to cover both new
      tables; `test/tenants.e2e-spec.ts`'s mocked `$transaction` resolved array updated to match
      the new array length/order. 447 unit / 168 e2e passing (unchanged from §4.20 — this fix
      added tests to existing suites, no new ones).
- [ ] **Not in this phase:** proxying this through the Next.js BFF layer — that's frontend work,
      and per the earlier design discussion, streaming through a Next.js Route Handler needs its
      own doc-check (`node_modules/next/dist/docs/`) before assuming it behaves like a normal
      proxied route. Flag as a follow-up frontend task when this phase is done.

## Phase 9 — Scheduled polling ingestion skeleton

- [x] `ModuleDataSourceAdapter` in `src/common/security-module/data-source-adapter.interface.ts`:
      `fetchSince(moduleName: ModuleName, config: Record<string, unknown>, since?: Date):
      Promise<RawRecord[]>` — one deliberate deviation from the plan's originally-sketched
      signature: added the leading `moduleName` param. `MockAdapter` is one object standing in
      for all six modules' adapters at once, so it genuinely needs to know which module it's
      being asked for at call time (a real per-vendor adapter wouldn't need this — it already
      knows its own module — but the interface has to serve both cases). Also added
      `RawRecord { timestamp, type, severity, data }` to `types.ts` — everything `ingest()`
      needs to build a `UnifiedEvent` except `tenantId`/`source`, which only the poller (not the
      adapter) knows. Exported `MODULE_DATA_SOURCE_ADAPTER` (a string DI token) from the same
      file — interfaces don't exist at runtime, so NestJS can't infer an injection token from
      `ModuleDataSourceAdapter` the way it does for a concrete class; this token is what lets
      `PollingService` depend on the interface instead of `MockAdapter` directly (caught by the
      compiler mid-build: typing the constructor param as the concrete class broke call sites
      that legitimately pass all three interface params, revealing the DI was accidentally
      binding to the narrower concrete type instead of the interface it's supposed to
      abstract over).
- [x] `src/polling/mock-adapter.ts` — one canned `RawRecord` per module (`ModuleName.VM` →
      `type: 'vulnerability'`, `EDR` → `'detection'`, `SIEM`/`SOAR`/`DFIR` → `'event'`, `CTI` →
      `'ioc'`), ignores `config`/`since` entirely (only meaningful once a real vendor is behind
      it). + `mock-adapter.spec.ts` (one record returned, correct `type` shape per module,
      confirms `config`/`since` really are ignored).
- [x] `PollingService` (`src/polling/`) — `@Cron(CronExpression.EVERY_5_MINUTES)` job iterating
      `TenantModule` rows where `isActive: true`. Routes each row to the right module service via
      a `Record<ModuleName, IngestibleModule>` registry built in the constructor from all six
      injected services (matches decision 5's generic `SecurityModule` contract — this is exactly
      the kind of code that contract exists to make possible, no per-module `switch`). Reads
      `since` from `TenantModule.config.lastSyncedAt` if present (`undefined` on a tenant-module's
      first-ever poll), calls the adapter, `ingest()`s every returned record, then writes a fresh
      `lastSyncedAt` back into `config` — reusing that existing `Json?` field rather than adding a
      schema column, per the plan's own text. + `polling.service.spec.ts` (no-`since`-on-first-
      poll, `since` parsed and other config keys preserved on subsequent polls, correct per-module
      routing for all six modules, multiple records per poll all ingested, `pollAll` iterates every
      active row). Verified with a real app boot (`NestFactory.create(AppModule)`, not just
      mocked-provider unit tests) that the full DI graph — the adapter token, all six service
      injections, `PrismaModule` — actually resolves. 310 unit / 128 e2e passing.
- [x] Real per-vendor adapters are explicitly **not** part of this plan — out of scope until
      real module API documentation exists (root `CLAUDE.md`'s "open input required" note).

## Phase 10 — Seed data for local dev / demo

- [x] New `prisma/seed-modules.ts` — deliberately a **separate** script from `seed.ts`, not
      wired into `prisma db seed`, run explicitly via `npm run seed:demo`. Kept apart on
      purpose: `seed.ts` stays scoped to its one narrow, security-sensitive job (one-time Super
      Admin bootstrap from `seed-data.json`); this one generates a large, throwaway demo
      dataset and should never fire implicitly off a routine `prisma migrate reset`.
      Per run: **5 tenants**, each with 8 users (2 Admins, 3 Analysts, 3 Viewers — 40 accounts
      total) and ~700 rows spread across all six modules + the asset feed (~3500 rows total).
      All seeded accounts share one password (`DemoPassw0rd!2026`, printed in full at the end of
      the run alongside every tenant/email/role) — deliberate simplification over unique
      per-account passwords, since the point is fast exploration across many personas while
      demoing, not per-account secrecy. Seeded with `mustChangePassword: false` — same
      precedent as the existing Super Admin bootstrap in `seed.ts` (a direct-Prisma seed
      script, not the `TenantsService`/`UsersService` API paths the `mustChangePassword: true`
      hard rule actually targets).
      Uses `@faker-js/faker` (new devDependency, seed-script-only, never imported by the actual
      application) for realistic company/person/network/vulnerability data at this volume, and
      pre-generates every row's UUID client-side so parent+child tables can be bulk-inserted via
      `createMany` without N+1 round trips (e.g. `VmVulnerability.assetId` set directly from a
      `VmAsset` id generated moments earlier, never re-fetched). `AssetFeedEntry` rows are
      written directly too, mirroring what `AssetService`'s real listeners would have produced
      for the same records — the one deliberate seed-only exception to that table's normal
      "only `AssetService` writes this" invariant, purely so the unified feed page has demo data
      without needing to replay the whole event chain for every row.
      Verified for real, not just "it ran without throwing": row counts confirmed directly
      against Postgres (5 new tenants, 40 new users, ~3500 new rows, cleanly additive alongside
      a pre-existing unrelated tenant already in the dev DB), then a live login with a seeded
      credential against a real running server, followed by real `GET` requests against
      `/api/vm/assets`, `/api/edr/detections`, `/api/siem/alerts`, `/api/cti/iocs`,
      `/api/soar/executions`, `/api/dfir/incidents`, and `/api/assets/feed` — all returned real
      seeded data, correctly tenant-scoped and paginated.
    - **Gap found and fixed 2026-08-08**, during a frontend-side "does the app match the
      backend's mock data" verification pass: that original `GET /api/assets/feed` check
      confirmed rows existed and were tenant-scoped, but never inspected `status`/
      `assignedToUserId` specifically — both were silently omitted from the EDR/SIEM/VM/DFIR
      `feedRows` construction (dropping to Prisma's column default, `null`, for every single
      row of those four sources), even though the *real* `AssetService` listeners this script
      claims to mirror always set them, and even though the seed script's own EDR/SIEM/VM/DFIR
      rows already carry a fully-decided `status`/`assignedToUserId` in scope at that exact
      point (`d.status`, `a.assignedToUserId`, etc. — the four loops literally had the values
      one property-name away and never copied them over). Effect: the frontend's Asset Feed
      page and dashboard KPIs (`isOpenFeedEntry`, "assigned to me") would show every demo row
      as unassigned and unopenable-as-open, even for tenants whose real per-module data (VM
      vulnerabilities, EDR detections, etc.) has plenty of assigned/in-progress records — the
      six module pages themselves were never affected, only the cross-module feed/dashboard
      view. Fixed by copying each source row's own `status`/`assignedToUserId` into its
      `feedRows` entry (SOAR/CTI correctly still have neither field — matches
      `handleSoarExecution`/`handleCtiIoc`, which never set them in the real listener either).
      `tsc --noEmit` clean; not re-run against a live seed (`npm run seed:demo`) in this pass —
      no Postgres available in this sandbox — worth a live re-verification next time someone
      runs it against a real database.
    - **`faker.seed(20260819)` added 2026-08-19**, at the top of `main()` — the tenant/company
      names and person names (and therefore emails, since those derive from the person name)
      were fully random per run until now, which is exactly right for a "throwaway demo
      dataset" but broke the moment `frontend/e2e/`'s new Playwright suite needed to hardcode
      real seeded identities in `frontend/e2e/fixtures/accounts.ts` instead of scraping them
      from the UI at runtime. Fixing the faker seed makes tenant/person identity generation
      reproducible across reseeds *in generation order* without touching the module data's own
      randomness at all — every `randomInt`/`pick`/`Math.random()` call for severities, counts,
      and assign/status distribution still varies run to run, since none of it goes through
      `faker`. Verified two ways, not just "it ran": ran `npm run seed:demo` once for real
      against the live dev DB and confirmed the resulting tenant/email set matches what's now
      hardcoded in `frontend/e2e/fixtures/accounts.ts`; separately confirmed the determinism
      claim itself in isolation — a standalone script replaying the same `faker.seed(20260819)`
      → `company.name()`/`person.firstName()`/`person.lastName()` call sequence twice in a row
      produced byte-identical output both times, including the exact "Crooks and Sons
      relationships" / "Katheryn Zemlak" values the real run produced. Not yet verified against
      a *second* real `npm run seed:demo` run on a fresh DB (would require deleting the current
      demo tenants first) — worth doing once, next time this file's own dev DB gets reset.

## Phase 11 — Final integration pass

- [x] One full end-to-end smoke test walking the real chain, done live 2026-08-05 against a real
      running server + Postgres, in a fresh dedicated tenant: an independent VM finding
      (`POST /vm/events`, unrelated to the rest of the chain) landed correctly on its own; then a
      SOAR playbook (`{severity: CRITICAL}` trigger) and a matching CTI IOC were seeded first, and
      one `POST /edr/events` walked the entire documented chain in a single request — EDR
      detection created → SIEM alert created at HIGH → CTI match escalated it to CRITICAL → SOAR
      fired against the playbook → DFIR incident created, linked to both the `SIEM_ALERT` and the
      `SOAR_EXECUTION`. Confirmed via `GET` on every module plus `GET /assets/feed` (all 7
      resulting entries present — VM×2, EDR, SIEM, CTI, SOAR, DFIR — correctly tenant-scoped).
      Cleanup (`DELETE /tenants/:id` on this tenant) doubled as a regression check for the
      task #52 fix, this time against a tenant with real data in *every* module simultaneously,
      not just the partial EDR+SIEM case that fix was originally verified against — deleted
      cleanly.
- [x] Revisited `GET /api/health`'s indicator list 2026-08-05 — **no new indicator added,
      deliberately**: the note's own trigger condition ("once modules gain their own independent
      external dependencies, e.g. SIEM's Elastic cluster") still isn't met. All six modules read
      and write through the same shared `PrismaService`/Postgres already covered by the
      `database` indicator, and Phase 9's polling explicitly runs on `MockAdapter` — fully
      synthetic, no real external connection — since real per-vendor adapters remain out of
      scope pending the still-open module-API-docs input from root `CLAUDE.md`. Revisit again
      once any module actually gains a real external dependency, not before.
- [x] Add a "Modules — Development Log" section to `docs/internship-report-backend.md`,
      mirroring §4's chronological format, and update this file's summary sections once the six
      modules are no longer "explicitly deferred." Done 2026-08-05 as §4.14, covering Phases
      0-6. Worth a light follow-up pass once Phases 7-11 (Asset aggregator, SSE, polling, seed,
      final integration) land, so the dev log doesn't drift from what's actually built.

## Phase 12 — Introduce `Logger` project-wide

Flagged 2026-08-04 while reviewing `VmService.healthCheck()`'s `catch` block, originally
deferred until Phases 0–11 were done so the convention could be applied once, consistently,
rather than piecemeal. **Reordered ahead of Phases 10–11 on 2026-08-05** — deliberately, not a
plan drift: Phase 10 (seed data) runs outside the NestJS app entirely (`ts-node
prisma/seed.ts`, no DI container, can't use the injectable `Logger` the way application code
does), and Phase 11 is verification work, not new application code — so the "avoid piecemeal
work" risk the original deferral was protecting against barely applied. Doing it first also
means Phase 11.1's full-chain smoke test gets to benefit from real logging while debugging,
instead of the other way around.

**Two-layer convention** (the user's stated goal: "Logger should handle all errors in the
codebase"):

- [x] **Global `AllExceptionsFilter`** (`src/common/filters/all-exceptions.filter.ts`, `@Catch()`,
      registered via `app.useGlobalFilters(...)` in `main.ts`) — the actual "handle all errors"
      mechanism. Every exception reaching the HTTP boundary, from anywhere, passes through this
      one place before becoming a response; it logs, then returns the exact same response NestJS
      would have sent anyway (`exception.getResponse()` forwarded unchanged for `HttpException`,
      the standard `{statusCode: 500, message: 'Internal server error'}` shape otherwise — same
      as NestJS's own default handler, verified no e2e test asserts on error-body shape before
      relying on this). 5xx / unknown thrown values log at `error` with the full stack and
      request context (method, path, `tenantId`/`userId` from `request.user` when authenticated);
      4xx logs at `debug` only — expected, client-driven outcomes aren't application faults, and
      logging every 404 at `error`/`warn` would drown out the failures that actually matter. This
      is what makes "all errors" true without needing try/catch added to every service method
      that doesn't have one today (`AssetService`, `EventsService`, `PollingService`, every
      `ingest()`, etc.) — anything unhandled already propagates up and hits this filter.
      + `all-exceptions.filter.spec.ts` (response shape preserved, 5xx logged at error with
      stack, 4xx logged at debug not error, tenantId/userId included when authenticated, `n/a`
      fallback when not). Verified live against a real running server: three real requests (401
      unauthenticated, 404 unknown route, 401 bad login) all preserved their exact original
      response bodies/status codes while the filter logged each at `DEBUG` with correct context.
- [x] **Per-class `Logger` instances, only where an error is caught and *not* rethrown** — the
      one gap the filter can't cover, since a swallowed error never reaches it. Fixed the six
      modules' `healthCheck()` methods (`vm`, `edr`, `siem`, `cti`, `soar`, `dfir` — the original
      motivating example): `catch {}` → `catch (error) { this.logger.error('<MODULE> health
      check failed', error); ... }`, each with a `private readonly logger = new
      Logger(XxxService.name);` field (the standard NestJS idiom — no custom wrapper, no DI
      token, since nothing here needs more than that). Also added `logger.warn(...)` to the
      three existing translate-and-rethrow blocks (`TenantsService.createTenantWithAdmin`,
      `UsersService.createUser`/`updateUserForTenant` — catch a Prisma P2002, throw
      `ConflictException`) — not required for coverage (the rethrow path already reaches the
      filter), but useful operational signal the filter's 4xx-skip would otherwise discard
      entirely (e.g. "someone hit a duplicate email during tenant creation"). Every touched spec
      updated to spy on `Logger.prototype.error`/`warn` and assert the call, not just the
      existing return-value/thrown-exception behavior. 316 unit / 128 e2e passing.
