import { Module } from '@nestjs/common';
import { SiemService } from './siem.service';
import { SiemController } from './siem.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [SiemController],
  providers: [SiemService],
  exports: [SiemService],
})
export class SiemModule {}
