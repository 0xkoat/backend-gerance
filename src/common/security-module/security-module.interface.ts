import { UnifiedEvent, ModuleHealth, BaseQueryFilters } from './types';

// The one contract every security module's service implements (VmService,
// EdrService, SiemService, CtiService, SoarService, DfirService) — this is
// what lets the orchestration layer and the scheduled poller
// (PollingService) call ingest()/query()/healthCheck() on any of the six
// without knowing which concrete module produced or owns the record.
// Generic over the module's own record type and its own filter shape
// (which must at least carry BaseQueryFilters) rather than the
// architecture spec's literal `query(filters): Promise<any[]>` — this is
// the one deliberate type-safety improvement over the spec (module plan
// decision 5).
export interface SecurityModule<TRecord, TFilters extends BaseQueryFilters> {
  ingest(event: UnifiedEvent): Promise<void>;
  query(filters: TFilters): Promise<TRecord[]>;
  healthCheck(): Promise<ModuleHealth>;
}
