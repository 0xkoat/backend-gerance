import { IsBoolean, IsObject, IsOptional } from 'class-validator';

export class UpdateTenantModuleDto {
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  @IsObject()
  config?: object;
}
