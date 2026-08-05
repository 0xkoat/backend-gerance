import { ModuleName, Severity } from '../../generated/prisma/enums';

export type EventType =
  'alert' | 'detection' | 'vulnerability' | 'event' | 'ioc';

export { Severity, ModuleName } from '../../generated/prisma/enums';

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

export interface CtiEnrichmentPayload {
  tenantId: string;
  alertId: string;
  severity: Severity;
}

export interface DfirIncidentPayload {
  tenantId: string;
  incidentId: string;
  title: string;
  severity: Severity;
  timestamp: Date;
}

export interface SoarExecutionPayload {
  tenantId: string;
  executionId: string;
  alertId: string;
  playbookId: string;
  playbookName: string;
  severity: Severity;
  timestamp: Date;
}
export interface RawRecord {
  timestamp: Date;
  type: EventType;
  severity: Severity;
  data: Record<string, unknown>;
}
