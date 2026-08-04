import { Module } from '@nestjs/common';
import { DfirService } from './dfir.service';
import { DfirController } from './dfir.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [DfirController],
  providers: [DfirService],
  exports: [DfirService],
})
export class DfirModule {}
