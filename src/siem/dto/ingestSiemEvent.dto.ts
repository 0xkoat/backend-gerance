import {
  IsEnum,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';
import { Severity } from '../../generated/prisma/enums';

export class IngestSiemEventDto {
  @IsIn(['event', 'alert'])
  type!: 'event' | 'alert';

  @IsEnum(Severity)
  severity!: Severity;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  title?: string;
}
