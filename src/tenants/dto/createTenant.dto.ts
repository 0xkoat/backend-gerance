import { IsNotEmpty, IsString } from 'class-validator';
import { CreateUserDto } from '../../users/dto/createUser.dto';

export class CreateTenantDto extends CreateUserDto {
  @IsString()
  @IsNotEmpty()
  tenantName!: string;
}
