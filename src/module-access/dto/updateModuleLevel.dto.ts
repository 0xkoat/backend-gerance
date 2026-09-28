import { IsEnum } from 'class-validator';
import { AnalystLevel } from '../../generated/prisma/enums';

export class UpdateModuleLevelDto {
  @IsEnum(AnalystLevel)
  minAnalystLevel!: AnalystLevel;
}
