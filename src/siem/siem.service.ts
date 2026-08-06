import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';
import { Prisma, SiemAlert, SiemLog } from '../generated/prisma/client';
import {
  ModuleName,
  Severity,
  SiemAlertStatus,
} from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import {
  BaseQueryFilters,
  ModuleHealth,
} from '../common/security-module/types';
import type {
  CtiEnrichmentPayload,
  UnifiedEvent,
} from '../common/security-module/types';
import {
  resolveAssignee,
  assertCanTransitionStatus,
} from '../common/assignment';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const TRANSITIONABLE_STATUSES: SiemAlertStatus[] = [
  SiemAlertStatus.ASSIGNED,
  SiemAlertStatus.ESCALATED,
];

export interface SiemQueryFilters extends BaseQueryFilters {
  status?: SiemAlertStatus;
}

const HIGH_SEVERITIES: Severity[] = [Severity.HIGH, Severity.CRITICAL];

@Injectable()
export class SiemService implements SecurityModule<
  SiemAlert,
  SiemQueryFilters
> {
  private readonly logger = new Logger(SiemService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // SecurityModule.ingest() implementation. Every incoming event always
  // becomes a SiemLog (the raw record); it's promoted to a SiemAlert too
  // only when it's explicitly typed 'alert' or its severity already crosses
  // the HIGH/CRITICAL threshold, a deliberately simple, explicit rule meant
  // to be revisited later, not a tuned heuristic.
  async ingest(event: UnifiedEvent): Promise<void> {
    const data = event.data as { title?: string };

    await this.prisma.siemLog.create({
      data: {
        tenantId: event.tenantId,
        source: event.source,
        eventType: event.type,
        severity: event.severity,
        rawData: event.data as Prisma.InputJsonValue,
        timestamp: event.timestamp,
      },
    });

    const isAlertWorthy =
      event.type === 'alert' || HIGH_SEVERITIES.includes(event.severity);
    if (!isAlertWorthy) {
      return;
    }

    const alert = await this.prisma.siemAlert.create({
      data: {
        tenantId: event.tenantId,
        title: data.title ?? `${event.source} ${event.type}`,
        severity: event.severity,
        rawData: event.data as Prisma.InputJsonValue,
      },
    });

    this.eventEmitter.emit('siem.alert.created', {
      ...event,
      severity: alert.severity,
      data: { ...event.data, title: alert.title, alertId: alert.id },
    });
  }

  // Second hop of the EDR -> SIEM -> CTI -> SOAR -> DFIR chain: every EDR
  // detection is re-ingested here as an explicit SIEM 'alert' (bypassing the
  // severity threshold in ingest() above), which is what turns EDR
  // telemetry into a SiemAlert unconditionally rather than only on
  // high-severity detections.
  @OnEvent('edr.detection.created')
  async handleEdrDetection(event: UnifiedEvent): Promise<void> {
    const data = event.data as { hostname: string; detectionName: string };

    await this.ingest({
      ...event,
      source: ModuleName.SIEM,
      type: 'alert',
      data: {
        ...event.data,
        title: `${data.detectionName} on ${data.hostname}`,
      },
    });
  }

  // CTI never calls SiemService directly. Cross-module reactions stay
  // decoupled by going through the event emitter only, never a direct
  // service-to-service call. This is the listener side of that: CtiService
  // emits the escalated severity, this applies it to the alert it matched
  // against.
  @OnEvent('cti.enrichment.applied')
  async handleEnrichment(payload: CtiEnrichmentPayload): Promise<void> {
    await this.prisma.siemAlert.updateMany({
      where: { id: payload.alertId, tenantId: payload.tenantId },
      data: { severity: payload.severity },
    });
  }

  async query(filters: SiemQueryFilters): Promise<SiemAlert[]> {
    const {
      tenantId,
      severity,
      assignedToUserId,
      dateFrom,
      dateTo,
      page = 1,
      pageSize = 20,
      status,
    } = filters;

    const where: Prisma.SiemAlertWhereInput = {
      tenantId,
      ...(severity && { severity }),
      ...(status && { status }),
      ...(assignedToUserId && { assignedToUserId }),
      ...((dateFrom || dateTo) && {
        createdAt: {
          ...(dateFrom && { gte: dateFrom }),
          ...(dateTo && { lte: dateTo }),
        },
      }),
    };

    return this.prisma.siemAlert.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    });
  }

  async healthCheck(): Promise<ModuleHealth> {
    try {
      const latest = await this.prisma.siemAlert.findFirst({
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      return {
        module: ModuleName.SIEM,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch (error) {
      this.logger.error('SIEM health check failed', error);
      return { module: ModuleName.SIEM, status: 'down' };
    }
  }

  async listLogs(tenantId: string): Promise<SiemLog[]> {
    return this.prisma.siemLog.findMany({
      where: { tenantId },
      orderBy: { timestamp: 'desc' },
    });
  }

  async assignAlert(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    requestedAssigneeId: string | undefined,
  ): Promise<SiemAlert> {
    const alert = await this.prisma.siemAlert.findUnique({ where: { id } });
    if (!alert || alert.tenantId !== tenantId) {
      throw new NotFoundException('Alert not found');
    }

    const assigneeId = await resolveAssignee(
      this.prisma,
      caller,
      tenantId,
      requestedAssigneeId,
    );

    const updated = await this.prisma.siemAlert.update({
      where: { id },
      data: {
        assignedToUserId: assigneeId,
        status: SiemAlertStatus.ASSIGNED,
      },
    });

    this.eventEmitter.emit('siem.alert.assigned', {
      tenantId,
      source: ModuleName.SIEM,
      recordId: updated.id,
      assignedToUserId: assigneeId,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  // Only the current assignee or an Admin can undo it (assertCanTransitionStatus
  // covers the same "who" question here as it does for escalate/resolve), and
  // only while the alert hasn't already moved past ASSIGNED/ESCALATED — an
  // alert that's already RESOLVED has nothing meaningful left to unassign.
  async unassignAlert(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
  ): Promise<SiemAlert> {
    const alert = await this.prisma.siemAlert.findUnique({ where: { id } });
    if (!alert || alert.tenantId !== tenantId) {
      throw new NotFoundException('Alert not found');
    }

    assertCanTransitionStatus(caller, alert.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(alert.status)) {
      throw new ConflictException(
        'Alert must be currently assigned and not yet resolved to be unassigned',
      );
    }

    const updated = await this.prisma.siemAlert.update({
      where: { id },
      data: { assignedToUserId: null, status: SiemAlertStatus.OPEN },
    });

    this.eventEmitter.emit('siem.alert.unassigned', {
      tenantId,
      source: ModuleName.SIEM,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  async updateAlertStatus(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    status: SiemAlertStatus,
  ): Promise<SiemAlert> {
    const alert = await this.prisma.siemAlert.findUnique({ where: { id } });
    if (!alert || alert.tenantId !== tenantId) {
      throw new NotFoundException('Alert not found');
    }

    assertCanTransitionStatus(caller, alert.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(alert.status)) {
      throw new ConflictException(
        'Alert must be assigned before it can be escalated or resolved',
      );
    }

    const updated = await this.prisma.siemAlert.update({
      where: { id },
      data: { status },
    });

    this.eventEmitter.emit('siem.alert.status_changed', {
      tenantId,
      source: ModuleName.SIEM,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }
}
