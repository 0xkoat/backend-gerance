import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
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
  private readonly logger = new Logger(SoarService.name);

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

  // Only checks isActive playbooks (a deactivated one is skipped without
  // being deleted) and only ever matches on a literal `severity` key.
  // TriggerConditionDto enforces that shape at creation time, so any other
  // key in triggerCondition would silently fail every check here. Execution
  // is fully simulated, there's no real SOAR engine to call, so every match
  // immediately creates a SUCCESS execution row, with no PENDING/RUNNING
  // window.
  async evaluateTriggers(
    tenantId: string,
    alertId: string,
    severity: Severity,
  ): Promise<void> {
    const playbooks = await this.prisma.soarPlaybook.findMany({
      where: { tenantId, isActive: true },
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

  // Fourth hop of the chain: every new SIEM alert is checked against active
  // playbooks at its original severity.
  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { alertId: string };
    await this.evaluateTriggers(event.tenantId, data.alertId, event.severity);
  }

  // An alert that didn't trigger a playbook at its original severity gets a
  // second chance here once CTI escalates it (e.g. LOW -> CRITICAL on an
  // IOC match).
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
    } catch (error) {
      this.logger.error('SOAR health check failed', error);
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

  async updatePlaybook(
    tenantId: string,
    id: string,
    dto: {
      name?: string;
      triggerCondition?: object;
      actions?: object;
      isActive?: boolean;
    },
  ): Promise<SoarPlaybook> {
    const playbook = await this.prisma.soarPlaybook.findUnique({
      where: { id },
    });
    if (!playbook || playbook.tenantId !== tenantId) {
      throw new NotFoundException('Playbook not found');
    }

    return this.prisma.soarPlaybook.update({
      where: { id },
      data: dto,
    });
  }

  // A hard delete would be blocked by the RESTRICT FK from SoarExecution
  // once a playbook has actually fired — those executions are an audit
  // trail, not something a playbook delete should silently take down with
  // it. Checked explicitly with a count() up front rather than attempting
  // the delete and catching the FK violation: under this project's Prisma 7
  // driver-adapter setup, that violation surfaces as a raw
  // DriverAdapterError (a Postgres-level error, `cause.kind ===
  // 'ForeignKeyConstraintViolation'`), not the `PrismaClientKnownRequestError`
  // with a `P20xx` code you'd get without the adapter — confirmed live
  // against the real dev DB. A pre-check avoids depending on that
  // adapter-internal error shape at all.
  async deletePlaybook(tenantId: string, id: string): Promise<void> {
    const playbook = await this.prisma.soarPlaybook.findUnique({
      where: { id },
    });
    if (!playbook || playbook.tenantId !== tenantId) {
      throw new NotFoundException('Playbook not found');
    }

    const executionCount = await this.prisma.soarExecution.count({
      where: { playbookId: id },
    });
    if (executionCount > 0) {
      throw new ConflictException(
        'Cannot delete a playbook that has existing executions — deactivate it instead (PATCH with isActive: false)',
      );
    }

    await this.prisma.soarPlaybook.delete({ where: { id } });
  }
}
