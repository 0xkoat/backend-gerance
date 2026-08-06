import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateTenantDto {
  @IsString()
  @IsNotEmpty()
  name!: string;
}
