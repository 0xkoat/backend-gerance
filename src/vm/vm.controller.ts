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
import { CreateVmAssetDto } from './dto/createVmAsset.dto';
import { UpdateVmAssetDto } from './dto/updateVmAsset.dto';
import { UpdateVulnerabilityStatusDto } from './dto/updateVulnerabilityStatus.dto';
import { IngestVmEventDto } from './dto/ingestVmEvent.dto';
import { VmQueryDto } from './dto/vmQuery.dto';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole, ModuleName } from '../generated/prisma/enums';
import { VmService } from './vm.service';
import { UnifiedEvent } from '../common/security-module/types';
import { requireTenantId } from '../common/require-tenant-id';
import { AssignDto } from '../common/dto/assign.dto';

@Controller('vm')
export class VmController {
  constructor(private readonly vmService: VmService) {}

  @Get('assets')
  async listAssets(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = requireTenantId(user);
    return this.vmService.listAssets(tenantId);
  }

  @Post('assets')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async createAsset(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createVmAssetDto: CreateVmAssetDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.createAsset(tenantId, createVmAssetDto);
  }

  @Patch('assets/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateAsset(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateVmAssetDto: UpdateVmAssetDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.updateAsset(tenantId, id, updateVmAssetDto);
  }

  @Delete('assets/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async deleteAsset(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    await this.vmService.deleteAsset(tenantId, id);
  }

  @Get('vulnerabilities')
  async queryVulnerabilities(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: VmQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.query({ ...query, tenantId });
  }

  @Patch('vulnerabilities/:id/status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateVulnerabilityStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateVulnerabilityStatusDto: UpdateVulnerabilityStatusDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.updateVulnerabilityStatus(
      tenantId,
      id,
      updateVulnerabilityStatusDto.status,
    );
  }

  @Post('vulnerabilities/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async assignVulnerability(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() assignDto: AssignDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.assignVulnerability(
      tenantId,
      id,
      user,
      assignDto.assignedToUserId,
    );
  }

  @Delete('vulnerabilities/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async unassignVulnerability(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    return this.vmService.unassignVulnerability(tenantId, id, user);
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() ingestVmEventDto: IngestVmEventDto,
  ) {
    const tenantId = requireTenantId(user);
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
