import { Module } from '@nestjs/common';
import { SoarService } from './soar.service';
import { SoarController } from './soar.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [SoarController],
  providers: [SoarService],
  exports: [SoarService],
})
export class SoarModule {}
