import { IsEnum } from 'class-validator';
import { ModuleName } from '../../generated/prisma/enums';

export class ActivateTenantModuleDto {
  @IsEnum(ModuleName)
  moduleName!: ModuleName;
}
