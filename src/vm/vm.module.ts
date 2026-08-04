import { Module } from '@nestjs/common';
import { VmService } from './vm.service';
import { VmController } from './vm.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [VmController],
  providers: [VmService],
  exports: [VmService],
})
export class VmModule {}
