import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Prisma, EdrDetection, EdrEndpoint } from '../generated/prisma/client';
import { ModuleName, EdrEndpointStatus } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import {
  BaseQueryFilters,
  ModuleHealth,
  UnifiedEvent,
} from '../common/security-module/types';

export interface EdrQueryFilters extends BaseQueryFilters {
  endpointId?: string;
}

@Injectable()
export class EdrService implements SecurityModule<
  EdrDetection,
  EdrQueryFilters
> {
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

    await this.prisma.edrDetection.create({
      data: {
        tenantId: event.tenantId,
        endpointId: endpoint.id,
        detectionName: data.detectionName,
        severity: event.severity,
        rawData: event.data as Prisma.InputJsonValue,
      },
    });

    this.eventEmitter.emit('edr.detection.created', event);
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
    } catch {
      return { module: ModuleName.EDR, status: 'down' };
    }
  }

  async listEndpoints(tenantId: string): Promise<EdrEndpoint[]> {
    return this.prisma.edrEndpoint.findMany({
      where: { tenantId },
      orderBy: { lastSeen: 'desc' },
    });
  }
}
