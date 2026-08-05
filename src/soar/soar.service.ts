import { Injectable } from '@nestjs/common';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';
import {
  Prisma,
  SoarExecution,
  SoarPlaybook,
} from '../generated/prisma/client';
import {
  ModuleName,
  Severity,
  SoarExecutionStatus,
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

export interface SoarQueryFilters extends BaseQueryFilters {
  status?: SoarExecutionStatus;
}

@Injectable()
export class SoarService implements SecurityModule<
  SoarExecution,
  SoarQueryFilters
> {
  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async ingest(event: UnifiedEvent): Promise<void> {
    const data = event.data as { alertId?: string };
    if (!data.alertId) {
      return;
    }
    await this.evaluateTriggers(event.tenantId, data.alertId, event.severity);
  }

  async evaluateTriggers(
    tenantId: string,
    alertId: string,
    severity: Severity,
  ): Promise<void> {
    const playbooks = await this.prisma.soarPlaybook.findMany({
      where: { tenantId },
    });

    for (const playbook of playbooks) {
      const condition = playbook.triggerCondition as Record<string, unknown>;
      const matches = Object.entries(condition).every(([key, value]) => {
        if (key === 'severity') {
          return severity === value;
        }
        return false;
      });
      if (!matches) {
        continue;
      }

      const execution = await this.prisma.soarExecution.create({
        data: {
          tenantId,
          playbookId: playbook.id,
          alertId,
          status: SoarExecutionStatus.SUCCESS,
          logs: `Playbook "${playbook.name}" executed (simulated).`,
        },
      });

      this.eventEmitter.emit('soar.execution.created', {
        tenantId,
        executionId: execution.id,
        alertId,
        playbookId: playbook.id,
        playbookName: playbook.name,
        severity,
        timestamp: execution.createdAt,
      });
    }
  }

  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { alertId: string };
    await this.evaluateTriggers(event.tenantId, data.alertId, event.severity);
  }

  @OnEvent('cti.enrichment.applied')
  async handleCtiEnrichment(payload: CtiEnrichmentPayload): Promise<void> {
    await this.evaluateTriggers(
      payload.tenantId,
      payload.alertId,
      payload.severity,
    );
  }

  async query(filters: SoarQueryFilters): Promise<SoarExecution[]> {
    const {
      tenantId,
      dateFrom,
      dateTo,
      page = 1,
      pageSize = 20,
      status,
    } = filters;

    const where: Prisma.SoarExecutionWhereInput = {
      tenantId,
      ...(status && { status }),
      ...((dateFrom || dateTo) && {
        createdAt: {
          ...(dateFrom && { gte: dateFrom }),
          ...(dateTo && { lte: dateTo }),
        },
      }),
    };

    return this.prisma.soarExecution.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    });
  }

  async healthCheck(): Promise<ModuleHealth> {
    try {
      const latest = await this.prisma.soarExecution.findFirst({
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      return {
        module: ModuleName.SOAR,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch {
      return { module: ModuleName.SOAR, status: 'down' };
    }
  }

  async listPlaybooks(tenantId: string): Promise<SoarPlaybook[]> {
    return this.prisma.soarPlaybook.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async createPlaybook(
    tenantId: string,
    dto: { name: string; triggerCondition: object; actions: object },
  ): Promise<SoarPlaybook> {
    return this.prisma.soarPlaybook.create({
      data: {
        tenantId,
        name: dto.name,
        triggerCondition: dto.triggerCondition,
        actions: dto.actions,
      },
    });
  }
}
