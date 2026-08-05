import { Inject, Injectable } from '@nestjs/common';
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

  @Cron(CronExpression.EVERY_5_MINUTES)
  async pollAll(): Promise<void> {
    const activeTenantModules = await this.prisma.tenantModule.findMany({
      where: { isActive: true },
    });

    for (const tenantModule of activeTenantModules) {
      await this.pollOne(tenantModule);
    }
  }

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
