import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Patch,
  Delete,
  Query,
} from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole, ModuleName } from '../generated/prisma/enums';
import { SiemService } from './siem.service';
import { IngestSiemEventDto } from './dto/ingestSiemEvent.dto';
import { UpdateSiemAlertStatusDto } from './dto/updateSiemAlertStatus.dto';
import { SiemQueryDto } from './dto/siemQuery.dto';
import type { UnifiedEvent } from '../common/security-module/types';
import { requireTenantId } from '../common/require-tenant-id';
import { AssignDto } from '../common/dto/assign.dto';

@Controller('siem')
export class SiemController {
  constructor(private readonly siemService: SiemService) {}

  @Get('logs')
  async listLogs(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = requireTenantId(user);
    return this.siemService.listLogs(tenantId);
  }

  @Get('alerts')
  async queryAlerts(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: SiemQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.siemService.query({ ...query, tenantId });
  }

  @Post('alerts/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async assignAlert(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() assignDto: AssignDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.siemService.assignAlert(
      tenantId,
      id,
      user,
      assignDto.assignedToUserId,
    );
  }

  @Delete('alerts/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async unassignAlert(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    return this.siemService.unassignAlert(tenantId, id, user);
  }

  @Patch('alerts/:id/status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateAlertStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateSiemAlertStatusDto: UpdateSiemAlertStatusDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.siemService.updateAlertStatus(
      tenantId,
      id,
      user,
      updateSiemAlertStatusDto.status,
    );
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestSiemEventDto: IngestSiemEventDto,
  ) {
    const tenantId = requireTenantId(user);
    const unifiedEvent: UnifiedEvent = {
      tenantId,
      timestamp: new Date(),
      source: ModuleName.SIEM,
      type: ingestSiemEventDto.type,
      severity: ingestSiemEventDto.severity,
      data: { title: ingestSiemEventDto.title },
    };
    return this.siemService.ingest(unifiedEvent);
  }
}
