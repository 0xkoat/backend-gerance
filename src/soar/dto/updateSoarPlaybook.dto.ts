import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';
import { TriggerConditionDto } from './triggerCondition.dto';

export class UpdateSoarPlaybookDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => TriggerConditionDto)
  triggerCondition?: TriggerConditionDto;

  @IsOptional()
  @IsObject()
  actions?: object;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
