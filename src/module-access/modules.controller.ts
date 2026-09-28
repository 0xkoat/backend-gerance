import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseEnumPipe,
  Patch,
  Post,
} from '@nestjs/common';
import { ModuleName, UserRole } from '../generated/prisma/client';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { requireTenantId } from '../common/require-tenant-id';
import { ModuleAccessService } from './module-access.service';
import { UpdateModuleLevelDto } from './dto/updateModuleLevel.dto';

// Tenant side of module access: what the caller can launch, the launch itself
// (a plain redirect target for now — no credentials are carried to the module),
// and the tenant Admin's per-module minimum analyst level.
@Controller('modules')
export class ModulesController {
  constructor(private readonly moduleAccessService: ModuleAccessService) {}

  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Get()
  listAvailable(@CurrentUser() user: AuthenticatedUser) {
    return this.moduleAccessService.listForUser(
      requireTenantId(user),
      user.role,
      user.analystLevel,
    );
  }

  @Roles(UserRole.ADMIN)
  @Get('launches')
  recentLaunches(@CurrentUser() user: AuthenticatedUser) {
    return this.moduleAccessService.recentLaunches(requireTenantId(user));
  }

  @Roles(UserRole.ADMIN)
  @Patch(':moduleName/level')
  setMinLevel(
    @CurrentUser() user: AuthenticatedUser,
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
    @Body() dto: UpdateModuleLevelDto,
  ) {
    return this.moduleAccessService.setMinLevel(
      requireTenantId(user),
      moduleName,
      dto.minAnalystLevel,
    );
  }

  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Post(':moduleName/launch')
  @HttpCode(200)
  launch(
    @CurrentUser() user: AuthenticatedUser,
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
  ) {
    return this.moduleAccessService.launch(
      user.userId,
      requireTenantId(user),
      moduleName,
    );
  }
}
