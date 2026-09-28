import {
  Body,
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { UserRole } from '../generated/prisma/client';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { TicketsService } from './tickets.service';
import { CreateTicketDto } from './dto/createTicket.dto';
import { UpdateTicketStatusDto } from './dto/updateTicketStatus.dto';
import { ListTicketsQueryDto } from './dto/listTicketsQuery.dto';

// Tenant Admins and Analysts raise tickets; Admins handle their tenant's, the
// Integration Admin handles MODULES tickets from every tenant. What each role
// can see and change is decided in TicketsService.
@Controller('tickets')
export class TicketsController {
  constructor(private readonly ticketsService: TicketsService) {}

  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Post()
  create(@CurrentUser() user: AuthenticatedUser, @Body() dto: CreateTicketDto) {
    return this.ticketsService.create(user, dto);
  }

  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.INTEGRATION_ADMIN)
  @Get()
  list(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListTicketsQueryDto,
  ) {
    return this.ticketsService.list(user, query.status);
  }

  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.INTEGRATION_ADMIN)
  @Get(':id')
  findOne(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.ticketsService.findOne(user, id);
  }

  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.INTEGRATION_ADMIN)
  @Patch(':id/status')
  updateStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateTicketStatusDto,
  ) {
    return this.ticketsService.updateStatus(user, id, dto.status);
  }
}
