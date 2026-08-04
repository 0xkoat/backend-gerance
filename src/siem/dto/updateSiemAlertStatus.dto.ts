import { IsEnum, IsOptional, IsUUID } from 'class-validator';
import { SiemAlertStatus } from '../../generated/prisma/enums';

export class UpdateSiemAlertStatusDto {
  @IsEnum(SiemAlertStatus)
  status!: SiemAlertStatus;

  @IsOptional()
  @IsUUID()
  assignedToUserId?: string;
}
