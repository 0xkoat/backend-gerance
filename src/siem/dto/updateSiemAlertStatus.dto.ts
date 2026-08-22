import { IsIn } from 'class-validator';
import { SiemAlertStatus } from '../../generated/prisma/enums';

// Only escalate/resolve go through this DTO — OPEN is set by ingest and
// ASSIGNED is set by the separate assign action, never directly by a caller.
export class UpdateSiemAlertStatusDto {
  @IsIn([SiemAlertStatus.ESCALATED, SiemAlertStatus.RESOLVED])
  status!: SiemAlertStatus;
}
