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
import { ModuleAccessService } from './module-access.service';
import { UpdateModuleEndpointDto } from './dto/updateModuleEndpoint.dto';

// Platform-wide module endpoints (one shared instance per module). Only an
// Integration Admin changes them or runs the connection test; a Super Admin
// can read them.
@Controller('module-endpoints')
export class ModuleEndpointsController {
  constructor(private readonly moduleAccessService: ModuleAccessService) {}

  @Roles(UserRole.INTEGRATION_ADMIN, UserRole.SUPER_ADMIN)
  @Get()
  list() {
    return this.moduleAccessService.listEndpoints();
  }

  @Roles(UserRole.INTEGRATION_ADMIN)
  @Patch(':moduleName')
  update(
    @CurrentUser() user: AuthenticatedUser,
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
    @Body() dto: UpdateModuleEndpointDto,
  ) {
    return this.moduleAccessService.updateEndpoint(
      moduleName,
      dto,
      user.userId,
    );
  }

  @Roles(UserRole.INTEGRATION_ADMIN)
  @Post(':moduleName/test')
  @HttpCode(200)
  test(
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
  ) {
    return this.moduleAccessService.testConnection(moduleName);
  }
}
