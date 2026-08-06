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
import { UserRole } from '../generated/prisma/enums';
import { DfirService } from './dfir.service';
import { UpdateDfirIncidentStatusDto } from './dto/updateDfirIncidentStatus.dto';
import { CreateDfirLinkDto } from './dto/createDfirLink.dto';
import { DfirQueryDto } from './dto/dfirQuery.dto';
import { requireTenantId } from '../common/require-tenant-id';
import { AssignDto } from '../common/dto/assign.dto';

@Controller('dfir')
export class DfirController {
  constructor(private readonly dfirService: DfirService) {}

  @Get('incidents')
  async queryIncidents(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: DfirQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.query({ ...query, tenantId });
  }

  @Get('incidents/:id')
  async getIncidentDetail(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.getIncidentDetail(tenantId, id);
  }

  @Post('incidents/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async assignIncident(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() assignDto: AssignDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.assignIncident(
      tenantId,
      id,
      user,
      assignDto.assignedToUserId,
    );
  }

  @Delete('incidents/:id/assign')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async unassignIncident(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.unassignIncident(tenantId, id, user);
  }

  @Patch('incidents/:id/status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateDfirIncidentStatusDto: UpdateDfirIncidentStatusDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.updateStatus(
      tenantId,
      id,
      user,
      updateDfirIncidentStatusDto.status,
    );
  }

  @Post('incidents/:id/links')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async createLink(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() createDfirLinkDto: CreateDfirLinkDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.dfirService.linkRecord(
      tenantId,
      id,
      createDfirLinkDto.sourceType,
      createDfirLinkDto.sourceId,
    );
  }

  @Delete('incidents/:id/links/:linkId')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async deleteLink(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Param('linkId') linkId: string,
  ) {
    const tenantId = requireTenantId(user);
    await this.dfirService.unlinkRecord(tenantId, id, linkId);
  }
}
