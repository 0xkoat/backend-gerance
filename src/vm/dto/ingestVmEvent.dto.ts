import {
  IsEnum,
  IsIP,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';
import { Severity } from '../../generated/prisma/enums';

export class IngestVmEventDto {
  @IsIP()
  assetIP!: string;

  @IsString()
  @IsNotEmpty()
  assetName!: string;

  @IsString()
  @IsNotEmpty()
  assetType!: string;

  @IsString()
  @IsNotEmpty()
  description!: string;

  @IsOptional()
  @IsString()
  cveId?: string;

  @IsEnum(Severity)
  severity!: Severity;
}
