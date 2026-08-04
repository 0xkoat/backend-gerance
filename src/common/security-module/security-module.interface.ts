import { UnifiedEvent, ModuleHealth, BaseQueryFilters } from './types';

export interface SecurityModule<TRecord, TFilters extends BaseQueryFilters> {
  ingest(event: UnifiedEvent): Promise<void>;
  query(filters: TFilters): Promise<TRecord[]>;
  healthCheck(): Promise<ModuleHealth>;
}
