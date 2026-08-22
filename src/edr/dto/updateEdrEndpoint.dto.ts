import {
  IsEnum,
  IsIP,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';
import { EdrEndpointStatus } from '../../generated/prisma/enums';

export class UpdateEdrEndpointDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  hostname?: string;

  @IsOptional()
  @IsIP()
  ip?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  os?: string;

  @IsOptional()
  @IsEnum(EdrEndpointStatus)
  status?: EdrEndpointStatus;
}
