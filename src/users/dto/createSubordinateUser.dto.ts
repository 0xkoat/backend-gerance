import { CreateUserDto } from './createUser.dto';
import { UserRole } from '../../generated/prisma/enums';
import { IsIn } from 'class-validator';

export class CreateSubordinateUserDto extends CreateUserDto {
  @IsIn([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
  role!: UserRole;
}
