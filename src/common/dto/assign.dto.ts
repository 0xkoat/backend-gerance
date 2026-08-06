import { IsOptional, IsUUID } from 'class-validator';

export class AssignDto {
  @IsOptional()
  @IsUUID()
  assignedToUserId?: string;
}
