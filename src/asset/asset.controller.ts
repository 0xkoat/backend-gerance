import { Controller, Get, Query } from '@nestjs/common';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { BaseQueryDto } from '../common/dto/base-query.dto';
import { AssetService } from './asset.service';
import { requireTenantId } from '../common/require-tenant-id';

@Controller('assets')
export class AssetController {
  constructor(private readonly assetService: AssetService) {}

  @Get('feed')
  async getUnifiedFeed(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: BaseQueryDto,
  ) {
    const tenantId = requireTenantId(user);
    return this.assetService.getUnifiedFeed(tenantId, { ...query, tenantId });
  }
}
