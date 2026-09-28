import { CreateUserDto } from './createUser.dto';
import { AnalystLevel, UserRole } from '../../generated/prisma/enums';
import { IsEnum, IsIn, IsOptional } from 'class-validator';

export class CreateSubordinateUserDto extends CreateUserDto {
  @IsIn([UserRole.ADMIN, UserRole.ANALYST])
  role!: UserRole;

  // Required when role is ANALYST, rejected otherwise — enforced in
  // UsersService (resolveAnalystLevel), since it depends on role.
  @IsOptional()
  @IsEnum(AnalystLevel)
  analystLevel?: AnalystLevel;
}
