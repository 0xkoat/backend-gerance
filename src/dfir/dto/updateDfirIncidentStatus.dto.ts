import { IsEnum } from 'class-validator';
import { DfirIncidentStatus } from '../../generated/prisma/enums';

export class UpdateDfirIncidentStatusDto {
  @IsEnum(DfirIncidentStatus)
  status!: DfirIncidentStatus;
}
