import { Type } from 'class-transformer';
import {
  IsNotEmpty,
  IsObject,
  IsString,
  ValidateNested,
} from 'class-validator';
import { TriggerConditionDto } from './triggerCondition.dto';

export class CreateSoarPlaybookDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @ValidateNested()
  @Type(() => TriggerConditionDto)
  triggerCondition!: TriggerConditionDto;

  @IsObject()
  actions!: object;
}
