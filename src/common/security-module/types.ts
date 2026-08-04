import { ModuleName, Severity } from 'src/generated/prisma/enums';

export type EventType =
  'alert' | 'detection' | 'vulnerability' | 'event' | 'ioc';

export { Severity, ModuleName } from 'src/generated/prisma/enums';

export interface UnifiedEvent {
  tenantId: string;
  timestamp: Date;
  source: ModuleName;
  type: EventType;
  severity: Severity;
  data: Record<string, unknown>;
}

export interface ModuleHealth {
  module: ModuleName;
  status: 'ok' | 'degraded' | 'down';
  lastIngestion?: Date;
}

export interface BaseQueryFilters {
  tenantId: string;
  severity?: Severity;
  dateFrom?: Date;
  dateTo?: Date;
  page?: number;
  pageSize?: number;
}
