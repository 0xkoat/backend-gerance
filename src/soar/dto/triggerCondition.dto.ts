import { IsEnum } from 'class-validator';
import { Severity } from '../../generated/prisma/enums';

// evaluateTriggers only ever matches on `severity` — validating the DTO to
// this exact shape means a typo'd trigger key is rejected at creation time
// instead of silently producing a playbook that can never fire.
export class TriggerConditionDto {
  @IsEnum(Severity)
  severity!: Severity;
}
