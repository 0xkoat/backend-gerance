import { IsEnum, IsIP, IsNotEmpty, IsString } from 'class-validator';
import { Severity } from '../../generated/prisma/enums';

export class IngestEdrEventDto {
  @IsString()
  @IsNotEmpty()
  hostname!: string;

  @IsIP()
  ip!: string;

  @IsString()
  @IsNotEmpty()
  os!: string;

  @IsString()
  @IsNotEmpty()
  detectionName!: string;

  @IsEnum(Severity)
  severity!: Severity;
}
