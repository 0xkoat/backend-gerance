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
import { UserRole, ModuleName, Severity } from '../generated/prisma/enums';
import { CtiService } from './cti.service';
import { CreateCtiIocDto } from './dto/createCtiIoc.dto';
import { CtiQueryDto } from './dto/ctiQuery.dto';
import type { UnifiedEvent } from '../common/security-module/types';

@Controller('cti')
export class CtiController {
  constructor(private readonly ctiService: CtiService) {}

  private requireTenantId(user: AuthenticatedUser): string {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    return user.tenantId;
  }

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
    const tenantId = this.requireTenantId(user);
    return this.ctiService.query({ ...query, tenantId });
  }

  @Post('iocs')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async createIoc(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createCtiIocDto: CreateCtiIocDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.ctiService.ingest(
      this.buildIocEvent(tenantId, createCtiIocDto),
    );
  }

  @Post('events')
  @Roles(UserRole.ADMIN)
  async ingestEvent(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createCtiIocDto: CreateCtiIocDto,
  ) {
    const tenantId = this.requireTenantId(user);
    return this.ctiService.ingest(
      this.buildIocEvent(tenantId, createCtiIocDto),
    );
  }
}
