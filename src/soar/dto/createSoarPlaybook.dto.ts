import { IsNotEmpty, IsObject, IsString } from 'class-validator';

export class CreateSoarPlaybookDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsObject()
  triggerCondition!: object;

  @IsObject()
  actions!: object;
}
