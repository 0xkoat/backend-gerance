import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { TicketsService } from './tickets.service';
import { NotificationsService } from './notifications.service';
import { TicketsController } from './tickets.controller';
import { NotificationsController } from './notifications.controller';

@Module({
  imports: [PrismaModule],
  controllers: [TicketsController, NotificationsController],
  providers: [TicketsService, NotificationsService],
})
export class TicketsModule {}
