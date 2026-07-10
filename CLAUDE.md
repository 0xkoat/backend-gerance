# Backend — SecOPs API

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
  password without ever knowing it). Self password changes must go through
  `PATCH /users/me/password`, which requires the current password.
- Demoting a tenant's last remaining Admin to a non-Admin role is rejected
  (`ConflictException`) — every tenant must always have at least one Admin.
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

# Conventions

- Don't guess at vulnerabilities or root causes — enumerate and verify first
- Manual, step-by-step fix instructions preferred over full file replacements when debugging
  existing configs/workflows (preserves credentials and state)
