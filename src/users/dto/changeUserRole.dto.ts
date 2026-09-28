import { IsEnum, IsIn, IsOptional } from 'class-validator';
import { AnalystLevel, UserRole } from '../../generated/prisma/enums';

export class ChangeUserRoleDto {
  @IsIn([UserRole.ADMIN, UserRole.ANALYST])
  role!: UserRole;

  // Required when role is ANALYST, rejected otherwise — enforced in
  // UsersService (resolveAnalystLevel), since it depends on role.
  @IsOptional()
  @IsEnum(AnalystLevel)
  analystLevel?: AnalystLevel;
}
