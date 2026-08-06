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
