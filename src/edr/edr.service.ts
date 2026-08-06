import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Prisma, EdrDetection, EdrEndpoint } from '../generated/prisma/client';
import {
  ModuleName,
  EdrEndpointStatus,
  EdrDetectionStatus,
} from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import {
  BaseQueryFilters,
  ModuleHealth,
  UnifiedEvent,
} from '../common/security-module/types';
import {
  resolveAssignee,
  assertCanTransitionStatus,
} from '../common/assignment';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

export interface EdrQueryFilters extends BaseQueryFilters {
  endpointId?: string;
}

// The only statuses a detection can move out of via updateDetectionStatus/
// unassignDetection. OPEN (never assigned yet) and terminal states aren't
// in this list, so a detection must be assigned before it can be
// escalated/resolved, and can't be unassigned once already resolved.
const TRANSITIONABLE_STATUSES: EdrDetectionStatus[] = [
  EdrDetectionStatus.ASSIGNED,
  EdrDetectionStatus.ESCALATED,
];

@Injectable()
export class EdrService implements SecurityModule<
  EdrDetection,
  EdrQueryFilters
> {
  private readonly logger = new Logger(EdrService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // SecurityModule.ingest() implementation and the start of the documented
  // EDR -> SIEM -> CTI -> SOAR -> DFIR orchestration chain: upserts the
  // reporting endpoint by (tenantId, hostname), creates the detection, then
  // emits 'edr.detection.created'. SiemService listens for this to turn it
  // into a SiemAlert. detectionId is stamped into the emitted event's data
  // so downstream listeners (and AssetService) can reference the created row.
  async ingest(event: UnifiedEvent): Promise<void> {
    const data = event.data as {
      hostname: string;
      ip: string;
      os: string;
      detectionName: string;
    };

    const endpoint = await this.prisma.edrEndpoint.upsert({
      where: {
        tenantId_hostname: {
          tenantId: event.tenantId,
          hostname: data.hostname,
        },
      },
      update: {
        ip: data.ip,
        os: data.os,
        status: EdrEndpointStatus.ONLINE,
        lastSeen: new Date(),
      },
      create: {
        tenantId: event.tenantId,
        hostname: data.hostname,
        ip: data.ip,
        os: data.os,
        status: EdrEndpointStatus.ONLINE,
      },
    });

    const detection = await this.prisma.edrDetection.create({
      data: {
        tenantId: event.tenantId,
        endpointId: endpoint.id,
        detectionName: data.detectionName,
        severity: event.severity,
        rawData: event.data as Prisma.InputJsonValue,
      },
    });

    this.eventEmitter.emit('edr.detection.created', {
      ...event,
      data: { ...event.data, detectionId: detection.id },
    });
  }

  async query(filters: EdrQueryFilters): Promise<EdrDetection[]> {
    const {
      tenantId,
      severity,
      assignedToUserId,
      dateFrom,
      dateTo,
      page = 1,
      pageSize = 20,
      endpointId,
    } = filters;

    const where: Prisma.EdrDetectionWhereInput = {
      tenantId,
      ...(severity && { severity }),
      ...(endpointId && { endpointId }),
      ...(assignedToUserId && { assignedToUserId }),
      ...((dateFrom || dateTo) && {
        createdAt: {
          ...(dateFrom && { gte: dateFrom }),
          ...(dateTo && { lte: dateTo }),
        },
      }),
    };

    return this.prisma.edrDetection.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    });
  }

  async healthCheck(): Promise<ModuleHealth> {
    try {
      const latest = await this.prisma.edrDetection.findFirst({
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      return {
        module: ModuleName.EDR,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch (error) {
      this.logger.error('EDR health check failed', error);
      return { module: ModuleName.EDR, status: 'down' };
    }
  }

  async listEndpoints(tenantId: string): Promise<EdrEndpoint[]> {
    return this.prisma.edrEndpoint.findMany({
      where: { tenantId },
      orderBy: { lastSeen: 'desc' },
    });
  }

  async updateEndpoint(
    tenantId: string,
    id: string,
    dto: {
      hostname?: string;
      ip?: string;
      os?: string;
      status?: EdrEndpointStatus;
    },
  ): Promise<EdrEndpoint> {
    const endpoint = await this.prisma.edrEndpoint.findUnique({
      where: { id },
    });
    if (!endpoint || endpoint.tenantId !== tenantId) {
      throw new NotFoundException('Endpoint not found');
    }

    return this.prisma.edrEndpoint.update({ where: { id }, data: dto });
  }

  // EdrDetection.endpointId RESTRICTs on this table, so a hard delete is
  // only allowed once no detection references it — mirroring
  // SoarService.deletePlaybook's execution-count guard. DECOMMISSIONED (the
  // status enum's fourth value, added alongside this) is the intended path
  // for retiring a host that still has detection history.
  async deleteEndpoint(tenantId: string, id: string): Promise<void> {
    const endpoint = await this.prisma.edrEndpoint.findUnique({
      where: { id },
    });
    if (!endpoint || endpoint.tenantId !== tenantId) {
      throw new NotFoundException('Endpoint not found');
    }

    const detectionCount = await this.prisma.edrDetection.count({
      where: { endpointId: id },
    });
    if (detectionCount > 0) {
      throw new ConflictException(
        'Cannot delete an endpoint that has existing detections — mark it DECOMMISSIONED instead (PATCH with status)',
      );
    }

    await this.prisma.edrEndpoint.delete({ where: { id } });
  }

  async assignDetection(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    requestedAssigneeId: string | undefined,
  ): Promise<EdrDetection> {
    const detection = await this.prisma.edrDetection.findUnique({
      where: { id },
    });
    if (!detection || detection.tenantId !== tenantId) {
      throw new NotFoundException('Detection not found');
    }

    const assigneeId = await resolveAssignee(
      this.prisma,
      caller,
      tenantId,
      requestedAssigneeId,
    );

    const updated = await this.prisma.edrDetection.update({
      where: { id },
      data: {
        assignedToUserId: assigneeId,
        status: EdrDetectionStatus.ASSIGNED,
      },
    });

    this.eventEmitter.emit('edr.detection.assigned', {
      tenantId,
      source: ModuleName.EDR,
      recordId: updated.id,
      assignedToUserId: assigneeId,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  async unassignDetection(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
  ): Promise<EdrDetection> {
    const detection = await this.prisma.edrDetection.findUnique({
      where: { id },
    });
    if (!detection || detection.tenantId !== tenantId) {
      throw new NotFoundException('Detection not found');
    }

    assertCanTransitionStatus(caller, detection.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(detection.status)) {
      throw new ConflictException(
        'Detection must be currently assigned and not yet resolved to be unassigned',
      );
    }

    const updated = await this.prisma.edrDetection.update({
      where: { id },
      data: { assignedToUserId: null, status: EdrDetectionStatus.OPEN },
    });

    this.eventEmitter.emit('edr.detection.unassigned', {
      tenantId,
      source: ModuleName.EDR,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  async updateDetectionStatus(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    status: EdrDetectionStatus,
  ): Promise<EdrDetection> {
    const detection = await this.prisma.edrDetection.findUnique({
      where: { id },
    });
    if (!detection || detection.tenantId !== tenantId) {
      throw new NotFoundException('Detection not found');
    }

    assertCanTransitionStatus(caller, detection.assignedToUserId);

    if (!TRANSITIONABLE_STATUSES.includes(detection.status)) {
      throw new ConflictException(
        'Detection must be assigned before it can be escalated or resolved',
      );
    }

    const updated = await this.prisma.edrDetection.update({
      where: { id },
      data: { status },
    });

    this.eventEmitter.emit('edr.detection.status_changed', {
      tenantId,
      source: ModuleName.EDR,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }
}
