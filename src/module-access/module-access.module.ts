import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { ModuleAccessService } from './module-access.service';
import { ConnectionProbe } from './connection-probe';
import { ModulesController } from './modules.controller';
import { ModuleEndpointsController } from './module-endpoints.controller';

@Module({
  imports: [PrismaModule],
  controllers: [ModulesController, ModuleEndpointsController],
  providers: [ModuleAccessService, ConnectionProbe],
})
export class ModuleAccessModule {}
