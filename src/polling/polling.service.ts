import { Inject, Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TenantModule } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { MODULE_DATA_SOURCE_ADAPTER } from '../common/security-module/data-source-adapter.interface';
import type { ModuleDataSourceAdapter } from '../common/security-module/data-source-adapter.interface';
import { ModuleName } from '../common/security-module/types';
import type { UnifiedEvent } from '../common/security-module/types';
import { VmService } from '../vm/vm.service';
import { EdrService } from '../edr/edr.service';
import { SiemService } from '../siem/siem.service';
import { CtiService } from '../cti/cti.service';
import { SoarService } from '../soar/soar.service';
import { DfirService } from '../dfir/dfir.service';

interface IngestibleModule {
  ingest(event: UnifiedEvent): Promise<void>;
}

@Injectable()
export class PollingService {
  private readonly logger = new Logger(PollingService.name);
  private readonly registry: Record<ModuleName, IngestibleModule>;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(MODULE_DATA_SOURCE_ADAPTER)
    private readonly adapter: ModuleDataSourceAdapter,
    vmService: VmService,
    edrService: EdrService,
    siemService: SiemService,
    ctiService: CtiService,
    soarService: SoarService,
    dfirService: DfirService,
  ) {
    this.registry = {
      [ModuleName.VM]: vmService,
      [ModuleName.EDR]: edrService,
      [ModuleName.SIEM]: siemService,
      [ModuleName.CTI]: ctiService,
      [ModuleName.SOAR]: soarService,
      [ModuleName.DFIR]: dfirService,
    };
  }

  // Only tenants that have actually activated a module (TenantModule.isActive)
  // get polled. A tenant with no activation row for a module is silently
  // skipped, not an error (see TenantsService.listModules for the CRUD path
  // that populates these rows; nothing auto-provisions them at tenant
  // creation, so a real tenant with zero activations polls nothing).
  @Cron(CronExpression.EVERY_5_MINUTES)
  async pollAll(): Promise<void> {
    const activeTenantModules = await this.prisma.tenantModule.findMany({
      where: { isActive: true },
    });

    for (const tenantModule of activeTenantModules) {
      try {
        await this.pollOne(tenantModule);
      } catch (error) {
        // One tenant's bad config or a failing ingest() shouldn't abort the
        // rest of this cycle's tenants — they just wait for the next run.
        this.logger.error(
          `Polling failed for tenant ${tenantModule.tenantId} / ${tenantModule.moduleName}`,
          error,
        );
      }
    }
  }

  // Routes to the right module service via the constructor-built registry
  // (the payoff of every module sharing the generic SecurityModule contract,
  // no per-module switch needed here). Reuses TenantModule.config (a Json?
  // column, no dedicated schema field) to persist lastSyncedAt between runs,
  // so each poll only fetches records newer than the previous one.
  async pollOne(tenantModule: TenantModule): Promise<void> {
    const config =
      (tenantModule.config as Record<string, unknown> | null) ?? {};
    const since = config.lastSyncedAt
      ? new Date(config.lastSyncedAt as string)
      : undefined;

    const records = await this.adapter.fetchSince(
      tenantModule.moduleName,
      config,
      since,
    );

    const moduleService = this.registry[tenantModule.moduleName];
    for (const record of records) {
      await moduleService.ingest({
        tenantId: tenantModule.tenantId,
        timestamp: record.timestamp,
        source: tenantModule.moduleName,
        type: record.type,
        severity: record.severity,
        data: record.data,
      });
    }

    await this.prisma.tenantModule.update({
      where: { id: tenantModule.id },
      data: {
        config: {
          ...config,
          lastSyncedAt: new Date().toISOString(),
        },
      },
    });
  }
}
