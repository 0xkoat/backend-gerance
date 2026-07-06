import { Controller, Get, Post, Body, Param, Delete } from '@nestjs/common';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/createTenant.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../generated/prisma/client';

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

  @Delete(':id')
  async deleteTenant(@Param('id') id: string) {
    const deletedTenant = await this.tenantsService.deleteTenantWithUsers(id);

    return {
      message: 'Tenant and all its accounts deleted successfully',
      id: deletedTenant.id,
    };
  }
}
