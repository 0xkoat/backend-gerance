import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { ModuleName } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import type {
  UnifiedEvent,
  SoarExecutionPayload,
  DfirIncidentPayload,
  RecordAssignedPayload,
  RecordStatusChangedPayload,
  RecordDeletedPayload,
  BaseQueryFilters,
} from '../common/security-module/types';
import type { AssetFeedEntry } from '../generated/prisma/client';

// Maintains AssetFeedEntry as a materialized, denormalized view over all six
// modules' `*.created` events, chosen over a live fan-out query across six
// tables so getUnifiedFeed can be one indexed ORDER BY/LIMIT/OFFSET query
// instead of merging six result sets in memory. Trade-off: the feed is
// eventually consistent with its source tables, never a source of truth
// itself.
@Injectable()
export class AssetService {
  constructor(private readonly prisma: PrismaService) {}

  // Six listeners below, one per module's `*.created` event — each maps
  // that module's own event/payload shape down to the shared
  // AssetFeedEntry row shape (tenantId/source/type/severity/timestamp/
  // summary/sourceId). `type` is always a hardcoded literal describing
  // what was just created ('detection', 'alert', ...), never forwarded
  // from the triggering event's own `type` field — that field isn't
  // reliable for this (e.g. a SIEM alert can be created from a `type:
  // 'event'` input once severity alone crosses the HIGH/CRITICAL
  // threshold in SiemService.ingest()) and AssetFeedEntry.type needs to
  // describe record kinds ('incident', 'execution') the ingestion-side
  // EventType doesn't cover at all. `status`/`assignedToUserId` are only
  // set for the four modules with an assign/status workflow (EDR, SIEM,
  // VM, DFIR per the module plan's workflow-scope decision) — CTI and
  // SOAR rows are created without either field, since neither model has
  // that column to begin with.
  @OnEvent('edr.detection.created')
  async handleEdrDetection(event: UnifiedEvent): Promise<void> {
    const data = event.data as {
      hostname: string;
      detectionName: string;
      detectionId: string;
    };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.EDR,
        type: 'detection',
        severity: event.severity,
        status: 'OPEN',
        assignedToUserId: null,
        timestamp: event.timestamp,
        summary: `${data.detectionName} on ${data.hostname}`,
        sourceId: data.detectionId,
      },
    });
  }

  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { title: string; alertId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.SIEM,
        type: 'alert',
        severity: event.severity,
        status: 'OPEN',
        assignedToUserId: null,
        timestamp: event.timestamp,
        summary: data.title,
        sourceId: data.alertId,
      },
    });
  }

  @OnEvent('soar.execution.created')
  async handleSoarExecution(payload: SoarExecutionPayload): Promise<void> {
    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: payload.tenantId,
        source: ModuleName.SOAR,
        type: 'execution',
        severity: payload.severity,
        timestamp: payload.timestamp,
        summary: `Playbook "${payload.playbookName}" executed`,
        sourceId: payload.executionId,
      },
    });
  }

  @OnEvent('vm.vulnerability.created')
  async handleVmVulnerability(event: UnifiedEvent): Promise<void> {
    const data = event.data as { description: string; vulnerabilityId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.VM,
        type: 'vulnerability',
        severity: event.severity,
        status: 'OPEN',
        assignedToUserId: null,
        timestamp: event.timestamp,
        summary: data.description,
        sourceId: data.vulnerabilityId,
      },
    });
  }

  @OnEvent('cti.ioc.created')
  async handleCtiIoc(event: UnifiedEvent): Promise<void> {
    const data = event.data as { type: string; value: string; iocId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.CTI,
        type: 'ioc',
        severity: event.severity,
        timestamp: event.timestamp,
        summary: `${data.type} IOC: ${data.value}`,
        sourceId: data.iocId,
      },
    });
  }

  @OnEvent('dfir.incident.created')
  async handleDfirIncident(payload: DfirIncidentPayload): Promise<void> {
    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: payload.tenantId,
        source: ModuleName.DFIR,
        type: 'incident',
        severity: payload.severity,
        status: 'OPEN',
        assignedToUserId: null,
        timestamp: payload.timestamp,
        summary: payload.title,
        sourceId: payload.incidentId,
      },
    });
  }

  // One handler per module for each of the two update event shapes, rather
  // than a single generic listener — @OnEvent's event name has to be a
  // literal string, so there's no way to subscribe once and branch on
  // source. Each just forwards to the same shared update.
  @OnEvent('siem.alert.assigned')
  async handleSiemAlertAssigned(payload: RecordAssignedPayload): Promise<void> {
    await this.applyAssignment(payload);
  }

  @OnEvent('siem.alert.status_changed')
  async handleSiemAlertStatusChanged(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyStatusChange(payload);
  }

  @OnEvent('edr.detection.assigned')
  async handleEdrDetectionAssigned(
    payload: RecordAssignedPayload,
  ): Promise<void> {
    await this.applyAssignment(payload);
  }

  @OnEvent('edr.detection.status_changed')
  async handleEdrDetectionStatusChanged(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyStatusChange(payload);
  }

  @OnEvent('dfir.incident.assigned')
  async handleDfirIncidentAssigned(
    payload: RecordAssignedPayload,
  ): Promise<void> {
    await this.applyAssignment(payload);
  }

  @OnEvent('dfir.incident.status_changed')
  async handleDfirIncidentStatusChanged(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyStatusChange(payload);
  }

  @OnEvent('vm.vulnerability.assigned')
  async handleVmVulnerabilityAssigned(
    payload: RecordAssignedPayload,
  ): Promise<void> {
    await this.applyAssignment(payload);
  }

  @OnEvent('siem.alert.unassigned')
  async handleSiemAlertUnassigned(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyUnassignment(payload);
  }

  @OnEvent('edr.detection.unassigned')
  async handleEdrDetectionUnassigned(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyUnassignment(payload);
  }

  @OnEvent('dfir.incident.unassigned')
  async handleDfirIncidentUnassigned(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyUnassignment(payload);
  }

  @OnEvent('vm.vulnerability.unassigned')
  async handleVmVulnerabilityUnassigned(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.applyUnassignment(payload);
  }

  @OnEvent('cti.ioc.deleted')
  async handleCtiIocDeleted(payload: RecordDeletedPayload): Promise<void> {
    await this.prisma.assetFeedEntry.deleteMany({
      where: {
        tenantId: payload.tenantId,
        source: payload.source,
        sourceId: payload.recordId,
      },
    });
  }

  // Sets both fields — assigning a record always sets who it's assigned to
  // and moves its status (e.g. OPEN -> ASSIGNED), never just one.
  private async applyAssignment(payload: RecordAssignedPayload): Promise<void> {
    await this.prisma.assetFeedEntry.updateMany({
      where: {
        tenantId: payload.tenantId,
        source: payload.source,
        sourceId: payload.recordId,
      },
      data: {
        status: payload.status,
        assignedToUserId: payload.assignedToUserId,
      },
    });
  }

  // Status only — an escalate/resolve action doesn't touch who the record
  // is assigned to (resolving deliberately keeps assignedToUserId as a
  // "who resolved this" record, it isn't cleared).
  private async applyStatusChange(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.prisma.assetFeedEntry.updateMany({
      where: {
        tenantId: payload.tenantId,
        source: payload.source,
        sourceId: payload.recordId,
      },
      data: { status: payload.status },
    });
  }

  // Both fields again, but the reverse of applyAssignment — status reverts
  // to OPEN and the assignee is cleared. Reuses RecordStatusChangedPayload's
  // shape rather than a dedicated type, since "unassigned" and
  // "status_changed" are genuinely the same payload shape on the wire (see
  // types.ts's own note on this).
  private async applyUnassignment(
    payload: RecordStatusChangedPayload,
  ): Promise<void> {
    await this.prisma.assetFeedEntry.updateMany({
      where: {
        tenantId: payload.tenantId,
        source: payload.source,
        sourceId: payload.recordId,
      },
      data: { status: payload.status, assignedToUserId: null },
    });
  }

  // The one real query this whole materialized table exists to serve:
  // real DB-level pagination over all six modules' records at once, backed
  // by the (tenantId, timestamp) index on AssetFeedEntry.
  async getUnifiedFeed(
    tenantId: string,
    filters: BaseQueryFilters,
  ): Promise<AssetFeedEntry[]> {
    return await this.prisma.assetFeedEntry.findMany({
      orderBy: { timestamp: 'desc' },
      where: {
        tenantId,
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.assignedToUserId && {
          assignedToUserId: filters.assignedToUserId,
        }),
        ...((filters.dateFrom || filters.dateTo) && {
          timestamp: {
            ...(filters.dateFrom && { gte: filters.dateFrom }),
            ...(filters.dateTo && { lte: filters.dateTo }),
          },
        }),
      },
      skip: ((filters.page || 1) - 1) * (filters.pageSize || 20),
      take: filters.pageSize || 20,
    });
  }
}
