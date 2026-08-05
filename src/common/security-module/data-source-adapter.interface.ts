import { ModuleName } from './types';
import type { RawRecord } from './types';

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
