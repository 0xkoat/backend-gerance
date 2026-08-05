import { Module } from '@nestjs/common';
import { AssetService } from './asset.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [AssetService],
})
export class AssetModule {}
