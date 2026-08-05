import { Controller, Get, Post, Body, Query } from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole } from '../generated/prisma/enums';
import { SoarService } from './soar.service';
import { CreateSoarPlaybookDto } from './dto/createSoarPlaybook.dto';
import { SoarQueryDto } from './dto/soarQuery.dto';
import { requireTenantId } from '../common/require-tenant-id';

@Controller('soar')
export class SoarController {
  constructor(private readonly soarService: SoarService) {}

  @Get('playbooks')
  async listPlaybooks(@CurrentUser() user: AuthenticatedUser) {
    const tenantId = requireTenantId(user);
    return this.soarService.listPlaybooks(tenantId);
  }

  @Post('playbooks')
  @Roles(UserRole.ADMIN)
  async createPlaybook(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createSoarPlaybookDto: CreateSoarPlaybookDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.soarService.createPlaybook(tenantId, createSoarPlaybookDto);
  }

  @Get('executions')
  async queryExecutions(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: SoarQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.soarService.query({ ...query, tenantId });
  }
}
