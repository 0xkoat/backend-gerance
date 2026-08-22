import { IsIP, IsNotEmpty, IsString } from 'class-validator';

export class CreateVmAssetDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsIP()
  @IsNotEmpty()
  ip!: string;

  @IsString()
  @IsNotEmpty()
  type!: string;
}
