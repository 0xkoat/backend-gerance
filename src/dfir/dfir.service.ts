import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';
import { DfirIncident, DfirLink, Prisma } from '../generated/prisma/client';
import {
  DfirIncidentStatus,
  DfirLinkSourceType,
  ModuleName,
  Severity,
} from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import {
  BaseQueryFilters,
  ModuleHealth,
} from '../common/security-module/types';
import type {
  SoarExecutionPayload,
  UnifiedEvent,
} from '../common/security-module/types';
import {
  resolveAssignee,
  assertCanTransitionStatus,
} from '../common/assignment';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

export interface DfirQueryFilters extends BaseQueryFilters {
  status?: DfirIncidentStatus;
}

export interface DfirLinkInput {
  sourceType: DfirLinkSourceType;
  sourceId: string;
}

const TRANSITIONABLE_STATUSES: DfirIncidentStatus[] = [
  DfirIncidentStatus.INVESTIGATING,
  DfirIncidentStatus.ESCALATED,
];

@Injectable()
export class DfirService implements SecurityModule<
  DfirIncident,
  DfirQueryFilters
> {
  private readonly logger = new Logger(DfirService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async ingest(event: UnifiedEvent): Promise<void> {
    const data = event.data as { title?: string };
    await this.createIncidentFromEvent(
      event.tenantId,
      data.title ?? `${event.source} ${event.type}`,
      event.severity,
      [],
    );
  }

  // The single choke point both ingest() and handleSoarExecution() funnel
  // through. Creates the incident, emits 'dfir.incident.created' once here
  // regardless of caller, then links any records passed in (e.g. the
  // originating SIEM alert and the SOAR execution that triggered it).
  async createIncidentFromEvent(
    tenantId: string,
    title: string,
    severity: Severity,
    links: DfirLinkInput[],
  ): Promise<DfirIncident> {
    const incident = await this.prisma.dfirIncident.create({
      data: { tenantId, title, severity },
    });

    this.eventEmitter.emit('dfir.incident.created', {
      tenantId,
      incidentId: incident.id,
      title,
      severity,
      timestamp: incident.createdAt,
    });

    for (const link of links) {
      await this.linkRecord(
        tenantId,
        incident.id,
        link.sourceType,
        link.sourceId,
      );
    }

    return incident;
  }

  async linkRecord(
    tenantId: string,
    incidentId: string,
    sourceType: DfirLinkSourceType,
    sourceId: string,
  ): Promise<DfirLink> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id: incidentId },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }

    // DfirLink has no FK on sourceId by design (it's a polymorphic pointer
    // across six different tables) - which means nothing at the DB layer
    // stops a caller from linking their own tenant's incident to another
    // tenant's real record id. Confirmed live: POST .../links with a
    // cross-tenant sourceId previously succeeded with no rejection. This is
    // the same tenant-ownership check every other id lookup in this codebase
    // already does after findUnique, just fanned out per sourceType since
    // there's no single parent table to check against here.
    await this.assertSourceRecordInTenant(tenantId, sourceType, sourceId);

    // Idempotent on retry (e.g. a client re-POSTing after a timeout on a
    // request that actually succeeded) rather than creating a second,
    // indistinguishable link for the same source record.
    const existingLink = await this.prisma.dfirLink.findFirst({
      where: { incidentId, sourceType, sourceId },
    });
    if (existingLink) {
      return existingLink;
    }

    return this.prisma.dfirLink.create({
      data: { tenantId, incidentId, sourceType, sourceId },
    });
  }

  private async assertSourceRecordInTenant(
    tenantId: string,
    sourceType: DfirLinkSourceType,
    sourceId: string,
  ): Promise<void> {
    let record: { tenantId: string } | null;

    switch (sourceType) {
      case DfirLinkSourceType.SIEM_ALERT:
        record = await this.prisma.siemAlert.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
      case DfirLinkSourceType.SIEM_LOG:
        record = await this.prisma.siemLog.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
      case DfirLinkSourceType.EDR_DETECTION:
        record = await this.prisma.edrDetection.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
      case DfirLinkSourceType.VM_VULNERABILITY:
        record = await this.prisma.vmVulnerability.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
      case DfirLinkSourceType.CTI_IOC:
        record = await this.prisma.ctiIoc.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
      case DfirLinkSourceType.SOAR_EXECUTION:
        record = await this.prisma.soarExecution.findUnique({
          where: { id: sourceId },
          select: { tenantId: true },
        });
        break;
    }

    if (!record || record.tenantId !== tenantId) {
      throw new NotFoundException(
        `${sourceType} record not found in this tenant`,
      );
    }
  }

  // Nothing references DfirLink (it's the leaf of the polymorphic link, not
  // a parent), so this is a plain, unguarded delete, no RESTRICT-FK
  // concern the way SoarPlaybook/EdrEndpoint/VmAsset deletion had.
  async unlinkRecord(
    tenantId: string,
    incidentId: string,
    linkId: string,
  ): Promise<void> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id: incidentId },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }

    const link = await this.prisma.dfirLink.findUnique({
      where: { id: linkId },
    });
    if (!link || link.tenantId !== tenantId || link.incidentId !== incidentId) {
      throw new NotFoundException('Link not found');
    }

    await this.prisma.dfirLink.delete({ where: { id: linkId } });
  }

  // Final hop of the EDR -> SIEM -> CTI -> SOAR -> DFIR chain: every SOAR
  // execution spawns a DFIR incident linked back to both the alert that
  // triggered it and the execution itself, so an analyst investigating the
  // incident can trace it back to its origin via getIncidentDetail's links.
  @OnEvent('soar.execution.created')
  async handleSoarExecution(payload: SoarExecutionPayload): Promise<void> {
    const alert = await this.prisma.siemAlert.findUnique({
      where: { id: payload.alertId },
    });
    if (!alert || alert.tenantId !== payload.tenantId) {
      return;
    }

    await this.createIncidentFromEvent(
      payload.tenantId,
      `Incident: ${alert.title}`,
      alert.severity,
      [
        {
          sourceType: DfirLinkSourceType.SIEM_ALERT,
          sourceId: payload.alertId,
        },
        {
          sourceType: DfirLinkSourceType.SOAR_EXECUTION,
          sourceId: payload.executionId,
        },
      ],
    );
  }

  async query(filters: DfirQueryFilters): Promise<DfirIncident[]> {
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

    const where: Prisma.DfirIncidentWhereInput = {
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

    return this.prisma.dfirIncident.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    });
  }

  async healthCheck(): Promise<ModuleHealth> {
    try {
      const latest = await this.prisma.dfirIncident.findFirst({
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      return {
        module: ModuleName.DFIR,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch (error) {
      this.logger.error('DFIR health check failed', error);
      return { module: ModuleName.DFIR, status: 'down' };
    }
  }

  // Incident plus its full DfirLink[], the data behind the incident-detail
  // view (an incident's links are its trace back to whatever records across
  // other modules led to it, per the polymorphic DfirLink design).
  async getIncidentDetail(
    tenantId: string,
    id: string,
  ): Promise<DfirIncident & { links: DfirLink[] }> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id },
      include: { links: true },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }
    return incident;
  }

  async assignIncident(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    requestedAssigneeId: string | undefined,
  ): Promise<DfirIncident> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }

    // Same reasoning as SiemService.assignAlert/EdrService.assignDetection:
    // assign starts or hands off open work, it shouldn't silently reopen an
    // incident that's already been contained or resolved.
    if (
      incident.status === DfirIncidentStatus.CONTAINED ||
      incident.status === DfirIncidentStatus.RESOLVED
    ) {
      throw new ConflictException(
        'Incident is already contained or resolved and cannot be reassigned',
      );
    }

    const assigneeId = await resolveAssignee(
      this.prisma,
      caller,
      tenantId,
      requestedAssigneeId,
    );

    const updated = await this.prisma.dfirIncident.update({
      where: { id },
      data: {
        assignedToUserId: assigneeId,
        status: DfirIncidentStatus.INVESTIGATING,
      },
    });

    this.eventEmitter.emit('dfir.incident.assigned', {
      tenantId,
      source: ModuleName.DFIR,
      recordId: updated.id,
      assignedToUserId: assigneeId,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  async unassignIncident(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
  ): Promise<DfirIncident> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }

    assertCanTransitionStatus(caller, incident.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(incident.status)) {
      throw new ConflictException(
        'Incident must be currently assigned and not yet contained/resolved to be unassigned',
      );
    }

    const updated = await this.prisma.dfirIncident.update({
      where: { id },
      data: { assignedToUserId: null, status: DfirIncidentStatus.OPEN },
    });

    this.eventEmitter.emit('dfir.incident.unassigned', {
      tenantId,
      source: ModuleName.DFIR,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  async updateStatus(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    status: DfirIncidentStatus,
  ): Promise<DfirIncident> {
    const incident = await this.prisma.dfirIncident.findUnique({
      where: { id },
    });
    if (!incident || incident.tenantId !== tenantId) {
      throw new NotFoundException('Incident not found');
    }

    assertCanTransitionStatus(caller, incident.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(incident.status)) {
      throw new ConflictException(
        'Incident must be assigned before it can be escalated, contained, or resolved',
      );
    }

    const updated = await this.prisma.dfirIncident.update({
      where: { id },
      data: { status },
    });

    this.eventEmitter.emit('dfir.incident.status_changed', {
      tenantId,
      source: ModuleName.DFIR,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }
}
