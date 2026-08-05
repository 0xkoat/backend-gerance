import { Injectable, NotFoundException } from '@nestjs/common';
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

export interface SiemQueryFilters extends BaseQueryFilters {
  status?: SiemAlertStatus;
}

const HIGH_SEVERITIES: Severity[] = [Severity.HIGH, Severity.CRITICAL];

@Injectable()
export class SiemService implements SecurityModule<
  SiemAlert,
  SiemQueryFilters
> {
  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

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
    } catch {
      return { module: ModuleName.SIEM, status: 'down' };
    }
  }

  async listLogs(tenantId: string): Promise<SiemLog[]> {
    return this.prisma.siemLog.findMany({
      where: { tenantId },
      orderBy: { timestamp: 'desc' },
    });
  }

  async updateAlertStatus(
    tenantId: string,
    id: string,
    status: SiemAlertStatus,
    assignedToUserId?: string,
  ): Promise<SiemAlert> {
    const alert = await this.prisma.siemAlert.findUnique({ where: { id } });
    if (!alert || alert.tenantId !== tenantId) {
      throw new NotFoundException('Alert not found');
    }

    return this.prisma.siemAlert.update({
      where: { id },
      data: { status, ...(assignedToUserId && { assignedToUserId }) },
    });
  }
}
