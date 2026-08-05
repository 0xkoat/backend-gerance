import { Injectable } from '@nestjs/common';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';
import { Prisma, CtiIoc } from '../generated/prisma/client';
import { CtiIocType, ModuleName, Severity } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import {
  BaseQueryFilters,
  ModuleHealth,
} from '../common/security-module/types';
import type { UnifiedEvent } from '../common/security-module/types';

export interface CtiQueryFilters extends BaseQueryFilters {
  type?: CtiIocType;
}

const MATCH_ESCALATION_SEVERITY = Severity.CRITICAL;

@Injectable()
export class CtiService implements SecurityModule<CtiIoc, CtiQueryFilters> {
  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async ingest(event: UnifiedEvent): Promise<void> {
    const data = event.data as {
      type: CtiIocType;
      value: string;
      confidence: number;
      source: string;
    };

    const where = {
      tenantId_type_value: {
        tenantId: event.tenantId,
        type: data.type,
        value: data.value,
      },
    };

    // upsert() alone can't tell us create vs. update, and cti.ioc.created
    // should only fire once per IOC — a re-ingested/re-submitted IOC just
    // refreshes confidence/source, it isn't a new feed-worthy record.
    const existing = await this.prisma.ctiIoc.findUnique({ where });

    const ioc = await this.prisma.ctiIoc.upsert({
      where,
      update: {
        confidence: data.confidence,
        source: data.source,
        rawData: event.data as Prisma.InputJsonValue,
      },
      create: {
        tenantId: event.tenantId,
        type: data.type,
        value: data.value,
        confidence: data.confidence,
        source: data.source,
        rawData: event.data as Prisma.InputJsonValue,
      },
    });

    if (!existing) {
      this.eventEmitter.emit('cti.ioc.created', {
        ...event,
        data: { ...event.data, iocId: ioc.id },
      });
    }
  }

  async checkMatch(tenantId: string, value: string): Promise<CtiIoc | null> {
    return this.prisma.ctiIoc.findFirst({ where: { tenantId, value } });
  }

  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { ip?: string; alertId: string };
    if (!data.ip) {
      return;
    }

    const match = await this.checkMatch(event.tenantId, data.ip);
    if (!match) {
      return;
    }

    this.eventEmitter.emit('cti.enrichment.applied', {
      tenantId: event.tenantId,
      alertId: data.alertId,
      severity: MATCH_ESCALATION_SEVERITY,
    });
  }

  async query(filters: CtiQueryFilters): Promise<CtiIoc[]> {
    const {
      tenantId,
      dateFrom,
      dateTo,
      page = 1,
      pageSize = 20,
      type,
    } = filters;

    const where: Prisma.CtiIocWhereInput = {
      tenantId,
      ...(type && { type }),
      ...((dateFrom || dateTo) && {
        createdAt: {
          ...(dateFrom && { gte: dateFrom }),
          ...(dateTo && { lte: dateTo }),
        },
      }),
    };

    return this.prisma.ctiIoc.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    });
  }

  async healthCheck(): Promise<ModuleHealth> {
    try {
      const latest = await this.prisma.ctiIoc.findFirst({
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      return {
        module: ModuleName.CTI,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch {
      return { module: ModuleName.CTI, status: 'down' };
    }
  }
}
