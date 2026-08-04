import {
  Controller,
  Get,
  ForbiddenException,
  Post,
  Body,
  Query,
} from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole, ModuleName } from '../generated/prisma/enums';
import { EdrService } from './edr.service';
import { IngestEdrEventDto } from './dto/ingestEdrEvent.dto';
import { EdrQueryDto } from './dto/edrQuery.dto';
import { UnifiedEvent } from '../common/security-module/types';

@Controller('edr')
export class EdrController {
  constructor(private readonly edrService: EdrService) {}

  private requireTenantId(user: AuthenticatedUser): string {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    return user.tenantId;
  }

  @Get('endpoints')
  async listEndpoints(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = this.requireTenantId(user);
    return this.edrService.listEndpoints(tenantId);
  }

  @Get('detections')
  async queryDetections(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: EdrQueryDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.edrService.query({ ...query, tenantId });
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestEdrEventDto: IngestEdrEventDto,
  ) {
    const tenantId = this.requireTenantId(user);
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
