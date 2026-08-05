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
import { UserRole } from '../generated/prisma/enums';
import { DfirService } from './dfir.service';
import { UpdateDfirIncidentStatusDto } from './dto/updateDfirIncidentStatus.dto';
import { CreateDfirLinkDto } from './dto/createDfirLink.dto';
import { DfirQueryDto } from './dto/dfirQuery.dto';
import { requireTenantId } from '../common/require-tenant-id';

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

  @Patch('incidents/:id')
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
}
