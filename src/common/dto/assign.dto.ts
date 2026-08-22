import { IsOptional, IsUUID } from 'class-validator';

// Body for every module's POST .../:id/assign route. Optional because an
// Analyst caller omits it entirely (resolveAssignee in assignment.ts
// self-assigns them regardless of what's sent); an Admin caller must
// supply it, enforced in resolveAssignee rather than here, since whether
// it's required depends on the caller's role, not just the shape of the body.
export class AssignDto {
  @IsOptional()
  @IsUUID()
  assignedToUserId?: string;
}
