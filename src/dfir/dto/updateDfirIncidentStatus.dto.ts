import { IsIn } from 'class-validator';
import { DfirIncidentStatus } from '../../generated/prisma/enums';

// Only escalate/contain/resolve go through this DTO — OPEN is the creation
// default and INVESTIGATING is set by the separate assign action, never
// directly by a caller.
export class UpdateDfirIncidentStatusDto {
  @IsIn([
    DfirIncidentStatus.ESCALATED,
    DfirIncidentStatus.CONTAINED,
    DfirIncidentStatus.RESOLVED,
  ])
  status!: DfirIncidentStatus;
}
