import { IsIn } from 'class-validator';
import { UserRole } from '../../generated/prisma/enums';

export class ChangeUserRoleDto {
  @IsIn([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
  role!: UserRole;
}