import {
  Controller,
  Get,
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
import { EdrService } from './edr.service';
import { IngestEdrEventDto } from './dto/ingestEdrEvent.dto';
import { EdrQueryDto } from './dto/edrQuery.dto';
import { UpdateEdrDetectionStatusDto } from './dto/updateEdrDetectionStatus.dto';
import { UnifiedEvent } from '../common/security-module/types';
import { requireTenantId } from '../common/require-tenant-id';
import { AssignDto } from '../common/dto/assign.dto';

@Controller('edr')
export class EdrController {
  constructor(private readonly edrService: EdrService) {}

  @Get('endpoints')
  async listEndpoints(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = requireTenantId(user);
    return this.edrService.listEndpoints(tenantId);
  }

  @Get('detections')
  async queryDetections(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: EdrQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.edrService.query({ ...query, tenantId });
  }

  @Post('detections/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async assignDetection(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() assignDto: AssignDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.edrService.assignDetection(
      tenantId,
      id,
      user,
      assignDto.assignedToUserId,
    );
  }

  @Patch('detections/:id/status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateDetectionStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateEdrDetectionStatusDto: UpdateEdrDetectionStatusDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.edrService.updateDetectionStatus(
      tenantId,
      id,
      user,
      updateEdrDetectionStatusDto.status,
    );
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestEdrEventDto: IngestEdrEventDto,
  ) {
    const tenantId = requireTenantId(user);
    const unifiedEvent: UnifiedEvent = {
      tenantId,
      timestamp: new Date(),
      source: ModuleName.EDR,
      type: 'detection',
      severity: ingestEdrEventDto.severity,
      data: {
        hostname: ingestEdrEventDto.hostname,
        ip: ingestEdrEventDto.ip,
        os: ingestEdrEventDto.os,
        detectionName: ingestEdrEventDto.detectionName,
      },
    };
    return this.edrService.ingest(unifiedEvent);
  }
}
