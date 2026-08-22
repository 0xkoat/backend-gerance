import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  ParseEnumPipe,
} from '@nestjs/common';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/createTenant.dto';
import { UpdateTenantDto } from './dto/updateTenant.dto';
import { ActivateTenantModuleDto } from './dto/activateTenantModule.dto';
import { UpdateTenantModuleDto } from './dto/updateTenantModule.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { ModuleName, UserRole } from '../generated/prisma/client';

// Class-level @Roles gates every route here to Super Admin. Tenant
// provisioning/module-activation is platform administration, never
// delegated to a tenant's own Admins.
@Controller('tenants')
@Roles(UserRole.SUPER_ADMIN)
export class TenantsController {
  constructor(private readonly tenantsService: TenantsService) {}

  @Post()
  async createTenant(@Body() createTenantDto: CreateTenantDto) {
    return this.tenantsService.createTenantWithAdmin(createTenantDto);
  }

  @Get()
  async getAllTenants() {
    return this.tenantsService.findAll();
  }

  @Get(':id')
  async getTenantById(@Param('id') id: string) {
    return this.tenantsService.findById(id);
  }

  @Patch(':id')
  async renameTenant(
    @Param('id') id: string,
    @Body() updateTenantDto: UpdateTenantDto,
  ) {
    return this.tenantsService.renameTenant(id, updateTenantDto.name);
  }

  @Delete(':id')
  async deleteTenant(@Param('id') id: string) {
    const deletedTenant = await this.tenantsService.deleteTenantWithUsers(id);

    return {
      message: 'Tenant and all its accounts deleted successfully',
      id: deletedTenant.id,
    };
  }

  @Get(':id/modules')
  async listModules(@Param('id') id: string) {
    return this.tenantsService.listModules(id);
  }

  @Post(':id/modules')
  async activateModule(
    @Param('id') id: string,
    @Body() activateTenantModuleDto: ActivateTenantModuleDto,
  ) {
    return this.tenantsService.activateModule(
      id,
      activateTenantModuleDto.moduleName,
      activateTenantModuleDto.config,
    );
  }

  @Patch(':id/modules/:moduleName')
  async updateModule(
    @Param('id') id: string,
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
    @Body() updateTenantModuleDto: UpdateTenantModuleDto,
  ) {
    return this.tenantsService.updateModule(
      id,
      moduleName,
      updateTenantModuleDto,
    );
  }

  @Delete(':id/modules/:moduleName')
  async deactivateModule(
    @Param('id') id: string,
    @Param('moduleName', new ParseEnumPipe(ModuleName)) moduleName: ModuleName,
  ) {
    await this.tenantsService.deactivateModule(id, moduleName);
  }
}
