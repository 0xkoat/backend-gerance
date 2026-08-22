import { Module } from '@nestjs/common';
import { PollingService } from './polling.service';
import { MockAdapter } from './mock-adapter';
import { MODULE_DATA_SOURCE_ADAPTER } from '../common/security-module/data-source-adapter.interface';
import { PrismaModule } from '../prisma/prisma.module';
import { VmModule } from '../vm/vm.module';
import { EdrModule } from '../edr/edr.module';
import { SiemModule } from '../siem/siem.module';
import { CtiModule } from '../cti/cti.module';
import { SoarModule } from '../soar/soar.module';
import { DfirModule } from '../dfir/dfir.module';

@Module({
  imports: [
    PrismaModule,
    VmModule,
    EdrModule,
    SiemModule,
    CtiModule,
    SoarModule,
    DfirModule,
  ],
  providers: [
    PollingService,
    { provide: MODULE_DATA_SOURCE_ADAPTER, useClass: MockAdapter },
  ],
})
export class PollingModule {}
