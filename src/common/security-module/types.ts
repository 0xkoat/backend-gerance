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

// Fired by every module's assign action — lets the SSE stream and the
// materialized asset feed reflect "who's working this" without either one
// needing to know each module's own record shape.
export interface RecordAssignedPayload {
  tenantId: string;
  source: ModuleName;
  recordId: string;
  assignedToUserId: string;
  status: string;
  timestamp: Date;
}

// Fired by every module's escalate/resolve-class status action. Not fired
// by ingest() itself — a record's initial status is always its schema
// default, assumed OPEN by every listener rather than carried in an event.
export interface RecordStatusChangedPayload {
  tenantId: string;
  source: ModuleName;
  recordId: string;
  status: string;
  timestamp: Date;
}
