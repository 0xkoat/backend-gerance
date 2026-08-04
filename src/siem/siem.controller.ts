import {
  Controller,
  Get,
  ForbiddenException,
  Post,
  Body,
  Param,
  Patch,
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

@Controller('siem')
export class SiemController {
  constructor(private readonly siemService: SiemService) {}

  private requireTenantId(user: AuthenticatedUser): string {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    return user.tenantId;
  }

  @Get('logs')
  async listLogs(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = this.requireTenantId(user);
    return this.siemService.listLogs(tenantId);
  }

  @Get('alerts')
  async queryAlerts(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: SiemQueryDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.siemService.query({ ...query, tenantId });
  }

  @Patch('alerts/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateAlertStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateSiemAlertStatusDto: UpdateSiemAlertStatusDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.siemService.updateAlertStatus(
      tenantId,
      id,
      updateSiemAlertStatusDto.status,
      updateSiemAlertStatusDto.assignedToUserId,
    );
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestSiemEventDto: IngestSiemEventDto,
  ) {
    const tenantId = this.requireTenantId(user);
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
