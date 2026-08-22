import { IsEnum, IsUUID } from 'class-validator';
import { DfirLinkSourceType } from '../../generated/prisma/enums';

export class CreateDfirLinkDto {
  @IsEnum(DfirLinkSourceType)
  sourceType!: DfirLinkSourceType;

  @IsUUID()
  sourceId!: string;
}
