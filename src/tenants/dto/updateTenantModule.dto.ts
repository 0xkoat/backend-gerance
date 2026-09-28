import { IsBoolean } from 'class-validator';

// Super Admin side of a tenant's module subscription: on/off only. The minimum
// analyst level belongs to the tenant's own Admin (PATCH /modules/:name/level).
export class UpdateTenantModuleDto {
  @IsBoolean()
  isActive!: boolean;
}
