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
                     │  • creates Analyst / Viewer accounts,      │
                     │    scoped to their own tenant_id only      │
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
- The very first Super Admin is bootstrapped by a one-time seed script (reads credentials
  from env vars, run directly against the DB) — not by any API call, since no user exists
  yet to authorize creating one.

# Conventions

- Don't guess at vulnerabilities or root causes — enumerate and verify first
- Manual, step-by-step fix instructions preferred over full file replacements when debugging
  existing configs/workflows (preserves credentials and state)
