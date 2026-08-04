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
import { UserRole } from '../generated/prisma/enums';
import { DfirService } from './dfir.service';
import { UpdateDfirIncidentStatusDto } from './dto/updateDfirIncidentStatus.dto';
import { CreateDfirLinkDto } from './dto/createDfirLink.dto';
import { DfirQueryDto } from './dto/dfirQuery.dto';

@Controller('dfir')
export class DfirController {
  constructor(private readonly dfirService: DfirService) {}

  private requireTenantId(user: AuthenticatedUser): string {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    return user.tenantId;
  }

  @Get('incidents')
  async queryIncidents(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: DfirQueryDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.dfirService.query({ ...query, tenantId });
  }

  @Get('incidents/:id')
  async getIncidentDetail(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.dfirService.getIncidentDetail(tenantId, id);
  }

  @Patch('incidents/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateDfirIncidentStatusDto: UpdateDfirIncidentStatusDto,
  ) {
    const tenantId = this.requireTenantId(user);
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
    const tenantId = this.requireTenantId(user);
    return this.dfirService.linkRecord(
      tenantId,
      id,
      createDfirLinkDto.sourceType,
      createDfirLinkDto.sourceId,
    );
  }
}
