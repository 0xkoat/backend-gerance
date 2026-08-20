import { ModuleName } from './types';
import type { RawRecord } from './types';

// What PollingService's scheduled job calls per active TenantModule row to
// pull new records from that module's external source. `moduleName` is
// only needed because MockAdapter (today's only implementation) stands in
// for all six modules at once and has to know which one it's being asked
// for — a real per-vendor adapter wouldn't need the parameter, since it
// would already know its own module, but the interface has to serve both.
// `since` is undefined on a tenant-module's first-ever poll (no
// lastSyncedAt yet); real adapters are out of scope until real module API
// documentation exists (root CLAUDE.md's "open input required" note).
export interface ModuleDataSourceAdapter {
  fetchSince(
    moduleName: ModuleName,
    config: Record<string, unknown>,
    since?: Date,
  ): Promise<RawRecord[]>;
}

// Interfaces don't exist at runtime, so NestJS can't infer an injection
// token from ModuleDataSourceAdapter the way it can from a concrete class —
// this token is what lets PollingService depend on the interface instead of
// the concrete MockAdapter, so a real adapter can be swapped in later
// without changing PollingService's types at all.
export const MODULE_DATA_SOURCE_ADAPTER = 'MODULE_DATA_SOURCE_ADAPTER';
