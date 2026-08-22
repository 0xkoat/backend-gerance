import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
} from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole, ModuleName, Severity } from '../generated/prisma/enums';
import { CtiService } from './cti.service';
import { CreateCtiIocDto } from './dto/createCtiIoc.dto';
import { UpdateCtiIocDto } from './dto/updateCtiIoc.dto';
import { CtiQueryDto } from './dto/ctiQuery.dto';
import type { UnifiedEvent } from '../common/security-module/types';
import { requireTenantId } from '../common/require-tenant-id';

@Controller('cti')
export class CtiController {
  constructor(private readonly ctiService: CtiService) {}

  // Shared by both createIoc (manual entry) and ingestEvent, both funnel
  // through the same ctiService.ingest(), so a hand-added IOC and a
  // vendor-fed one are indistinguishable once stored.
  private buildIocEvent(tenantId: string, dto: CreateCtiIocDto): UnifiedEvent {
    return {
      tenantId,
      timestamp: new Date(),
      source: ModuleName.CTI,
      type: 'ioc',
      severity: Severity.LOW,
      data: {
        type: dto.type,
        value: dto.value,
        confidence: dto.confidence,
        source: dto.source,
      },
    };
  }

  @Get('iocs')
  async queryIocs(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: CtiQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.ctiService.query({ ...query, tenantId });
  }

  @Post('iocs')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async createIoc(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createCtiIocDto: CreateCtiIocDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.ctiService.ingest(
      this.buildIocEvent(tenantId, createCtiIocDto),
    );
  }

  @Patch('iocs/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async updateIoc(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() updateCtiIocDto: UpdateCtiIocDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.ctiService.updateIoc(tenantId, id, updateCtiIocDto);
  }

  @Delete('iocs/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async deleteIoc(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const tenantId = requireTenantId(user);
    await this.ctiService.deleteIoc(tenantId, id);
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createCtiIocDto: CreateCtiIocDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.ctiService.ingest(
      this.buildIocEvent(tenantId, createCtiIocDto),
    );
  }
}
