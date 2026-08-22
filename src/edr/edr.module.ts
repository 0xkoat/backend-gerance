import { Module } from '@nestjs/common';
import { EdrService } from './edr.service';
import { EdrController } from './edr.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [EdrController],
  providers: [EdrService],
  exports: [EdrService],
})
export class EdrModule {}
