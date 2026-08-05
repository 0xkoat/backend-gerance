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

# Security modules — architecture spec (not yet built)

Source: root `CLAUDE.md`'s "Security modules architecture" section points here for detail.
Status as of 2026-08-04: **none of the six modules are implemented yet** — only
`auth`/`users`/`tenants`/`health` exist under `src/`. `TenantModule` (model) and
`ModuleName`/`ModuleSourceType` (enums) already exist in `prisma/schema.prisma` — this is
the platform-level "which modules is this tenant subscribed to" table (matches the spec's
`tenant_modules`), not any per-module data table. The module-specific tables below (`siem_*`,
`edr_*`, etc.) don't exist in the schema yet.

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

# API surface & operational hardening

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
- [ ] `SoarService implements SecurityModule<SoarExecution, SoarQueryFilters>`: `ingest()`,
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

- [ ] `EventsController` — `@Sse('events/stream')`, subscribes to the shared `EventEmitter2`,
      filters by `request.user.tenantId` before forwarding anything (never leak cross-tenant
      events over this stream). + a unit test asserting the tenant filter actually excludes
      other tenants' events.
- [ ] Manual verification: `curl -N` against the endpoint with a real JWT, ingest something via
      an existing module route in another terminal, confirm the event arrives on the stream.
- [ ] **Not in this phase:** proxying this through the Next.js BFF layer — that's frontend work,
      and per the earlier design discussion, streaming through a Next.js Route Handler needs its
      own doc-check (`node_modules/next/dist/docs/`) before assuming it behaves like a normal
      proxied route. Flag as a follow-up frontend task when this phase is done.

## Phase 9 — Scheduled polling ingestion skeleton

- [ ] `interface ModuleDataSourceAdapter { fetchSince(config: Record<string, unknown>, since?:
      Date): Promise<RawRecord[]> }` in `src/common/security-module/`.
- [ ] `MockAdapter implements ModuleDataSourceAdapter` — returns canned fake records per module,
      so the cron path is real and testable without any actual vendor access (per root
      `CLAUDE.md`: module API docs are still an open input).
- [ ] `PollingService` — `@Cron()` job iterating `TenantModule` rows where `isActive: true`,
      calling the right module's adapter (via the `MockAdapter` for now) + that module's
      `ingest()`, then updating a `lastSyncedAt` value in `TenantModule.config`.
      + `polling.service.spec.ts`.
- [ ] Real per-vendor adapters are explicitly **not** part of this plan — out of scope until
      real module API documentation exists (root `CLAUDE.md`'s "open input required" note).

## Phase 10 — Seed data for local dev / demo

- [ ] Extend `prisma/seed.ts` (or a new `prisma/seed-modules.ts`, wired the same way) with
      representative rows across all six modules for the existing seeded tenant(s) — this is
      what lets you demo the dashboard without waiting on Phase 9's polling or any real vendor.

## Phase 11 — Final integration pass

- [ ] One full end-to-end smoke test walking the real chain manually (or scripted): a VM finding
      (independent), then a POSTed EDR event that produces a SIEM alert, gets CTI-checked,
      triggers a SOAR execution, and lands a DFIR incident linking all of it — same "live,
      not just unit-tested" verification standard the rest of this project has held itself to.
- [ ] Revisit `GET /api/health`'s indicator list per this file's own existing note ("Add new
      named indicators here... once modules gain their own independent external dependencies").
- [x] Add a "Modules — Development Log" section to `docs/internship-report-backend.md`,
      mirroring §4's chronological format, and update this file's summary sections once the six
      modules are no longer "explicitly deferred." Done 2026-08-05 as §4.14, covering Phases
      0-6. Worth a light follow-up pass once Phases 7-11 (Asset aggregator, SSE, polling, seed,
      final integration) land, so the dev log doesn't drift from what's actually built.

## Phase 12 — Deferred: introduce `Logger` project-wide

Flagged 2026-08-04 while reviewing `VmService.healthCheck()`'s `catch` block: this codebase
doesn't use NestJS's `Logger` anywhere yet (confirmed via repo-wide grep) — every `catch` today
either rethrows or silently swallows. That's fine for now (the plain `catch {}` fix in
`VmService.healthCheck()` matches existing convention), but a real logging convention would
make failures like a health check going `'down'` actually debuggable instead of just visible as
a status flag with no context. **Deliberately deferred, not forgotten** — don't introduce
`Logger` piecemeal in one module's catch block; it should be a single, consistent decision
applied across the whole codebase (auth, users, tenants, and all six security modules) once the
module build-out (Phases 0–11) is done, not bolted on ad hoc along the way.

- [ ] Decide and apply a project-wide `Logger` convention (where it's injected, what gets
      logged at what level, whether it replaces or supplements existing silent/rethrow error
      handling) across the whole backend, once Phases 0–11 are complete.
