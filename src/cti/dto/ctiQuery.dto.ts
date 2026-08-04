import { IsEnum, IsOptional } from 'class-validator';
import { BaseQueryDto } from '../../common/dto/base-query.dto';
import { CtiIocType } from '../../generated/prisma/enums';

export class CtiQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsEnum(CtiIocType)
  type?: CtiIocType;
}
