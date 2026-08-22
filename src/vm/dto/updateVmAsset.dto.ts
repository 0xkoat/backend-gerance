import { IsIP, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UpdateVmAssetDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @IsOptional()
  @IsIP()
  ip?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  type?: string;
}
