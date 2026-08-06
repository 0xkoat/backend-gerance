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

    return this.prisma.dfirLink.create({
      data: { tenantId, incidentId, sourceType, sourceId },
    });
  }

  // Nothing references DfirLink (it's the leaf of the polymorphic link, not
  // a parent), so this is a plain, unguarded delete — no RESTRICT-FK
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
