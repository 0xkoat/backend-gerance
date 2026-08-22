import { IsIn } from 'class-validator';
import { EdrDetectionStatus } from '../../generated/prisma/enums';

// Only escalate/resolve go through this DTO — OPEN is set by ingest and
// ASSIGNED is set by the separate assign action, never directly by a caller.
export class UpdateEdrDetectionStatusDto {
  @IsIn([EdrDetectionStatus.ESCALATED, EdrDetectionStatus.RESOLVED])
  status!: EdrDetectionStatus;
}
