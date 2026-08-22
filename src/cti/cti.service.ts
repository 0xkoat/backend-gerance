import { Injectable, Logger, NotFoundException } from '@nestjs/common';
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
  private readonly logger = new Logger(CtiService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // SecurityModule.ingest() implementation, shared by POST /cti/iocs and
  // POST /cti/events. Upserts on the (tenantId, type, value) identity key so
  // a re-submitted IOC refreshes confidence/source instead of duplicating.
  //
  // Tries create() first and only falls back to update() on a P2002 conflict
  // (rather than a pre-upsert findUnique to decide create-vs-update) so the
  // create-or-update decision is enforced by the DB's own unique constraint,
  // not a separate read that can go stale under concurrent ingests of the
  // same IOC — that gap previously let two concurrent requests both see "no
  // existing row" and both emit 'cti.ioc.created' for what the DB correctly
  // stored as a single row.
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

    let ioc: CtiIoc;
    let created: boolean;
    try {
      ioc = await this.prisma.ctiIoc.create({
        data: {
          tenantId: event.tenantId,
          type: data.type,
          value: data.value,
          confidence: data.confidence,
          source: data.source,
          rawData: event.data as Prisma.InputJsonValue,
        },
      });
      created = true;
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        ioc = await this.prisma.ctiIoc.update({
          where,
          data: {
            confidence: data.confidence,
            source: data.source,
            rawData: event.data as Prisma.InputJsonValue,
          },
        });
        created = false;
      } else {
        throw error;
      }
    }

    if (created) {
      this.eventEmitter.emit('cti.ioc.created', {
        ...event,
        data: { ...event.data, iocId: ioc.id },
      });
    }
  }

  async checkMatch(
    tenantId: string,
    value: string,
    type: CtiIocType,
  ): Promise<CtiIoc | null> {
    return this.prisma.ctiIoc.findFirst({ where: { tenantId, type, value } });
  }

  async updateIoc(
    tenantId: string,
    id: string,
    dto: { confidence?: number; source?: string },
  ): Promise<CtiIoc> {
    const ioc = await this.prisma.ctiIoc.findUnique({ where: { id } });
    if (!ioc || ioc.tenantId !== tenantId) {
      throw new NotFoundException('IOC not found');
    }

    return this.prisma.ctiIoc.update({ where: { id }, data: dto });
  }

  // A true hard delete — the one deliberate exception to every other
  // module's "records are never deleted, only status/assignee changes"
  // pattern. A false-positive IOC needs to actually disappear, not just be
  // marked resolved. AssetService listens for the emitted event below to
  // remove the matching AssetFeedEntry row too, so the deletion doesn't
  // leave a dangling row in the unified feed.
  async deleteIoc(tenantId: string, id: string): Promise<void> {
    const ioc = await this.prisma.ctiIoc.findUnique({ where: { id } });
    if (!ioc || ioc.tenantId !== tenantId) {
      throw new NotFoundException('IOC not found');
    }

    await this.prisma.ctiIoc.delete({ where: { id } });

    this.eventEmitter.emit('cti.ioc.deleted', {
      tenantId,
      source: ModuleName.CTI,
      recordId: id,
      timestamp: new Date(),
    });
  }

  // Third hop of the EDR -> SIEM -> CTI -> SOAR -> DFIR chain: every new
  // SIEM alert is checked against known IOCs by IP; a match escalates the
  // alert to CRITICAL via 'cti.enrichment.applied' rather than CtiService
  // touching SiemAlert directly, keeping the two modules decoupled. Scoped
  // to IP-type IOCs specifically (not value alone) so a HASH- or DOMAIN-type
  // IOC whose value string happens to collide with an alert's IP can't
  // produce a semantically wrong match.
  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { ip?: string; alertId: string };
    if (!data.ip) {
      return;
    }

    const match = await this.checkMatch(event.tenantId, data.ip, CtiIocType.IP);
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
    } catch (error) {
      this.logger.error('CTI health check failed', error);
      return { module: ModuleName.CTI, status: 'down' };
    }
  }
}
