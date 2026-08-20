import { ModuleName, Severity } from '../../generated/prisma/enums';

// The shared vocabulary every one of the six security modules (and the
// orchestration layer between them) speaks — see root CLAUDE.md's
// "Security modules architecture" section for the design this file
// implements. Nothing here is module-specific; a module-specific shape
// (SiemAlert, VmVulnerability, ...) only exists inside that module's own
// service/DTOs and inside UnifiedEvent.data below, never up here.

export type EventType =
  'alert' | 'detection' | 'vulnerability' | 'event' | 'ioc';

export { Severity, ModuleName } from '../../generated/prisma/enums';

// The one envelope shape every ingest() call receives, regardless of which
// module or which real (or, today, mocked) upstream engine produced it —
// this is what lets the orchestration layer (event emitters between
// modules) never need to know a source system's native payload shape.
// `data` is deliberately untyped: each module's own ingest() is
// responsible for pulling the fields it recognizes out of it and mapping
// known ones onto real relational columns (rawData Json? on every
// per-record table keeps the original payload too, so nothing recognized
// later is silently lost to an earlier, narrower mapping).
export interface UnifiedEvent {
  tenantId: string;
  timestamp: Date;
  source: ModuleName;
  type: EventType;
  severity: Severity;
  data: Record<string, unknown>;
}

// Returned by every module's healthCheck() — deliberately the same three
// fields regardless of module, so a future aggregate health view (or
// GET /health's per-indicator breakdown) can treat all six uniformly.
export interface ModuleHealth {
  module: ModuleName;
  status: 'ok' | 'degraded' | 'down';
  lastIngestion?: Date;
}

// The query() contract's filter shape. Every module's own *QueryFilters
// type extends this rather than reinventing severity/date-range/pagination
// per module — see security-module.interface.ts's generic SecurityModule<>
// for where this plugs in.
export interface BaseQueryFilters {
  tenantId: string;
  severity?: Severity;
  assignedToUserId?: string;
  dateFrom?: Date;
  dateTo?: Date;
  page?: number;
  pageSize?: number;
}

// Emitted by CtiService when a SIEM alert's value matches a known IOC —
// SIEM listens for this and applies the escalated severity to the alert it
// names. CTI never calls SiemService directly to do this itself (decision
// 6 in the module plan: cross-module reactions go through the event
// emitter only, to keep the modules as decoupled in code as the
// architecture doc claims they are conceptually).
export interface CtiEnrichmentPayload {
  tenantId: string;
  alertId: string;
  severity: Severity;
}

// Emitted by DfirService.createIncidentFromEvent — the one choke point
// every path that creates a DfirIncident (a direct ingest() and the
// soar.execution.created listener) funnels through, so this is the only
// place that needs to build this payload.
export interface DfirIncidentPayload {
  tenantId: string;
  incidentId: string;
  title: string;
  severity: Severity;
  timestamp: Date;
}

// Emitted by SoarService.evaluateTriggers after a (simulated, decision 8 in
// the module plan) playbook execution — DFIR listens for this to open an
// incident linked back to both the triggering alert and this execution.
export interface SoarExecutionPayload {
  tenantId: string;
  executionId: string;
  alertId: string;
  playbookId: string;
  playbookName: string;
  severity: Severity;
  timestamp: Date;
}

// What a ModuleDataSourceAdapter.fetchSince() returns per poll — everything
// ingest() needs to build a UnifiedEvent *except* tenantId/source, which
// only the poller calling the adapter knows, not the adapter itself (see
// data-source-adapter.interface.ts).
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

// Fired when a record is actually removed (not just status/assignee
// changed) — currently only CTI IOC deletion. No status field, unlike
// RecordStatusChangedPayload: the record no longer exists to have one.
export interface RecordDeletedPayload {
  tenantId: string;
  source: ModuleName;
  recordId: string;
  timestamp: Date;
}
