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
import { CreateVmAssetDto } from './dto/createVmAsset.dto';
import { UpdateVulnerabilityStatusDto } from './dto/updateVulnerabilityStatus.dto';
import { IngestVmEventDto } from './dto/ingestVmEvent.dto';
import { VmQueryDto } from './dto/vmQuery.dto';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole, ModuleName } from '../generated/prisma/enums';
import { VmService } from './vm.service';
import { UnifiedEvent } from '../common/security-module/types';

@Controller('vm')
export class VmController {
  constructor(private readonly vmService: VmService) {}

  private requireTenantId(user: AuthenticatedUser): string {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    return user.tenantId;
  }

  @Get('assets')
  async listAssets(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = this.requireTenantId(user);
    return this.vmService.listAssets(tenantId);
  }

  @Post('assets')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async createAsset(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createVmAssetDto: CreateVmAssetDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.vmService.createAsset(tenantId, createVmAssetDto);
  }

  @Get('vulnerabilities')
  async queryVulnerabilities(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: VmQueryDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.vmService.query({ ...query, tenantId });
  }

  @Patch('vulnerabilities/:id/status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateVulnerabilityStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateVulnerabilityStatusDto: UpdateVulnerabilityStatusDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.vmService.updateVulnerabilityStatus(
      tenantId,
      id,
      updateVulnerabilityStatusDto.status,
    );
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestVmEventDto: IngestVmEventDto,
  ) {
    const tenantId = this.requireTenantId(user);
    const unifiedEvent: UnifiedEvent = {
      tenantId,
      timestamp: new Date(),
      source: ModuleName.VM,
      type: 'vulnerability',
      severity: ingestVmEventDto.severity,
      data: {
        assetIP: ingestVmEventDto.assetIP,
        assetName: ingestVmEventDto.assetName,
        assetType: ingestVmEventDto.assetType,
        description: ingestVmEventDto.description,
        cveId: ingestVmEventDto.cveId,
      },
    };
    return this.vmService.ingest(unifiedEvent);
  }
}
