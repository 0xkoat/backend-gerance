import { Module } from '@nestjs/common';
import { CtiService } from './cti.service';
import { CtiController } from './cti.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [CtiController],
  providers: [CtiService],
  exports: [CtiService],
})
export class CtiModule {}
